#!/usr/bin/env python3
"""Read-only Linux security scan. Prints one JSON document on stdout.

Changes nothing on the server. Standard library only (Python 3.6+).
Usage: collect.py --web-roots /var/www [--recent-days 7] [--max-files 50000]
"""
import argparse
import glob
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.request

FINDINGS = []


def add(severity, area, title, detail="", fix=""):
    FINDINGS.append({"severity": severity, "area": area, "title": title,
                     "detail": detail, "fix": fix})


def run(cmd, timeout=60):
    """Run a command, return (rc, stdout). Never raises."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout, universal_newlines=True)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def read(path, limit=2_000_000):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


# ---------------------------------------------------------------- system
def system_info():
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read("/etc/os-release"), re.M))
    up = read("/proc/uptime").split()
    return {
        "hostname": socket.gethostname(),
        "os": osr.get("PRETTY_NAME", "unknown"),
        "os_family": "redhat" if os.path.exists("/etc/redhat-release") else "debian",
        "kernel": os.uname().release,
        "uptime_days": round(float(up[0]) / 86400, 1) if up else None,
        "scan_time": time.strftime("%Y-%m-%d %H:%M %Z"),
    }


# ---------------------------------------------------------------- network
def firewall_active():
    rc, out = run(["ufw", "status"])
    if rc == 0 and "Status: active" in out:
        return "ufw"
    rc, out = run(["firewall-cmd", "--state"])
    if rc == 0 and "running" in out:
        return "firewalld"
    rc, out = run(["nft", "list", "ruleset"])
    if out.count("\n") > 10:
        return "nftables rules"
    return "none"


def listening_ports(firewall):
    rc, out = run(["ss", "-H", "-tulpn"])
    ports = []
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        proto, local = cols[0], cols[4]
        proc = re.search(r'"([^"]+)"', line)
        addr, _, port = local.rpartition(":")
        ports.append({"proto": proto, "address": addr, "port": port,
                      "process": proc.group(1) if proc else "?"})

    def is_service(p):
        if p["address"] not in ("0.0.0.0", "*", "[::]", "::"):
            return False
        if p["port"] in ("22", "80", "443"):
            return False
        if p["proto"] == "udp":
            # DHCP/NTP/mDNS clients and temporary client sockets (browsers etc.) are not services
            if p["port"] in ("68", "546", "123", "323", "5353") or not p["port"].isdigit() or int(p["port"]) >= 32768:
                return False
        return True

    seen = set()
    for p in filter(is_service, ports):
        key = (p["proto"], p["port"])
        if key in seen:
            continue
        seen.add(key)
        if firewall == "none":
            add("medium", "Network", "Service open to the internet on port %s/%s (%s)" % (p["port"], p["proto"], p["process"]),
                "It listens on all interfaces and no firewall is active, so anyone can reach it.",
                "Bind it to 127.0.0.1 if only local apps use it, or turn on the firewall and close the port.")
        else:
            add("low", "Network", "Service listening on all interfaces: port %s/%s (%s)" % (p["port"], p["proto"], p["process"]),
                "The firewall (%s) is active; check that this port is blocked unless it must be public." % firewall,
                "Bind it to 127.0.0.1 or stop the service if it is not needed.")
    return ports


# ---------------------------------------------------------------- accounts
def accounts():
    users, uid0, shell_users = [], [], []
    for p in pwd.getpwall():
        has_shell = not re.search(r"(nologin|false|sync|shutdown|halt)$", p.pw_shell or "")
        if p.pw_uid == 0 and p.pw_name != "root":
            uid0.append(p.pw_name)
        if has_shell and (p.pw_uid == 0 or p.pw_uid >= 1000) and p.pw_name != "nobody":
            shell_users.append({"user": p.pw_name, "uid": p.pw_uid, "home": p.pw_dir, "shell": p.pw_shell})
        users.append(p)
    for name in uid0:
        add("high", "Accounts", "Extra account with root rights (UID 0): %s" % name,
            "Only 'root' should have UID 0. A second one is a classic backdoor.",
            "Check who created it; remove it or give it a normal UID.")

    empty = []
    for line in read("/etc/shadow").splitlines():
        f = line.split(":")
        if len(f) > 1 and f[1] == "":
            empty.append(f[0])
    for name in empty:
        add("high", "Accounts", "Account without a password: %s" % name,
            "Anyone can log in as this user without a password.",
            "Lock it with 'passwd -l %s' or set a strong password." % name)

    sudo_rules = []
    files = ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*"))
    for f in files:
        for line in read(f).splitlines():
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("Defaults") or "ALL" not in s:
                continue
            sudo_rules.append({"file": f, "rule": s})
            if "NOPASSWD" in s:
                add("low", "Accounts", "sudo without password: %s" % s,
                    "Defined in %s. A stolen session gets full root without any prompt." % f,
                    "Keep NOPASSWD only for automation accounts that really need it.")

    keys = []
    for p in users:
        path = os.path.join(p.pw_dir or "/nonexistent", ".ssh", "authorized_keys")
        if os.path.isfile(path):
            n = sum(1 for ln in read(path).splitlines() if ln.strip() and not ln.startswith("#"))
            keys.append({"user": p.pw_name, "file": path, "keys": n})
            if p.pw_uid == 0 and n:
                add("low", "Accounts", "root has %d SSH key(s) in %s" % (n, path),
                    "Keys for root are a direct way in; check each one is known.",
                    "Remove keys you do not recognise; prefer logging in as a normal user + sudo.")
    return {"shell_users": shell_users, "uid0_extra": uid0, "empty_passwords": empty,
            "sudo_rules": sudo_rules, "ssh_keys": keys}


# ---------------------------------------------------------------- persistence
SUSPICIOUS_CMD = re.compile(
    r"((curl|wget)\s[^|;]*\|\s*(ba|z|da)?sh|base64\s+(-d|--decode)|/dev/shm/|/var/tmp/|(^|\s)/tmp/\S+|"
    r"\bnc\s+-|\bncat\b|bash\s+-i|python[0-9.]*\s+-c|perl\s+-e|xmrig|minerd|kdevtmpfsi|kinsing|chmod\s+\+x\s+/tmp)",
    re.I)


def cron_jobs():
    jobs = []
    paths = ["/etc/crontab"] + glob.glob("/etc/cron.d/*") + glob.glob("/var/spool/cron/*") + \
        glob.glob("/var/spool/cron/crontabs/*")
    for f in paths:
        if not os.path.isfile(f):
            continue
        for line in read(f).splitlines():
            s = line.strip()
            if not s or s.startswith("#") or re.match(r"^[A-Z_]+=", s):
                continue
            jobs.append({"file": f, "line": s})
            if SUSPICIOUS_CMD.search(s):
                add("high", "Persistence", "Suspicious cron job in %s" % f, s[:300],
                    "Check what this command downloads or runs. Remove it if nobody on your team added it.")
    return jobs


def systemd_units():
    local = []
    for f in sorted(glob.glob("/etc/systemd/system/*.service") + glob.glob("/etc/systemd/system/*/*.service")):
        if os.path.islink(f):
            continue
        txt = read(f)
        execs = re.findall(r"^\s*Exec\w*=\s*(.+)$", txt, re.M)
        local.append({"unit": f, "exec": execs[:3]})
        for e in execs:
            if SUSPICIOUS_CMD.search(e):
                add("high", "Persistence", "Suspicious service %s" % os.path.basename(f), e[:300],
                    "A system service runs a command from a temp folder or downloads code. Investigate and disable it.")
    return local


MINERS = re.compile(r"(xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|cryptonight|stratum\+tcp|nicehash)", re.I)


def processes():
    bad = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink("/proc/%s/exe" % pid)
        except OSError:
            exe = ""
        cmd = read("/proc/%s/cmdline" % pid).replace("\x00", " ").strip()
        reason = None
        if MINERS.search(cmd) or MINERS.search(exe):
            reason = "looks like a crypto miner"
        elif re.match(r"^(/tmp|/dev/shm|/var/tmp)/", exe):
            reason = "runs from a temporary folder"
        elif exe.startswith("/memfd:"):
            reason = "runs only from memory (memfd, no file on disk)"
        elif exe.endswith(" (deleted)") and not re.search(r"/(usr|lib|opt|snap)/", exe):
            reason = "its program file was deleted after it started"
        if reason:
            bad.append({"pid": pid, "exe": exe, "cmd": cmd[:200], "reason": reason})
            add("high", "Processes", "Process %s %s" % (pid, reason), (exe or cmd)[:300],
                "Find out what started it (parent process, cron, services). Common sign of a compromise.")
    return bad


def suid_files():
    rc, out = run(["find", "/", "-xdev", "-type", "f", "-perm", "-4000"], timeout=120)
    files = [f for f in out.splitlines() if f]
    odd = [f for f in files if re.match(r"^(/tmp|/var/tmp|/dev/shm|/home|/var/www|/srv)/", f)]
    for f in odd:
        add("high", "Files", "Program with root (SUID) rights in an unusual place: %s" % f,
            "SUID programs outside system folders are often used to get root back after a break-in.",
            "Remove the SUID bit ('chmod u-s %s') or delete the file if it is not yours." % f)
    return {"count": len(files), "unusual": odd}


# ---------------------------------------------------------------- web
WEBSHELL = re.compile(
    rb"(eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(|"
    rb"assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|"
    rb"(shell_exec|system|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|"
    rb"preg_replace\s*\(\s*['\"].*/e['\"]|"
    rb"\$\w+\s*=\s*\$_(POST|GET|REQUEST|COOKIE)\[[^\]]+\]\s*;\s*@?\$\w+\s*\(|"
    rb"FilesMan|c99shell|r57shell|WSO\s+\d|b374k)", re.I)
PHP_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc")


def web_scan(roots, recent_days, max_files):
    res = {"roots": [], "files_scanned": 0, "suspicious": [], "php_in_uploads": [],
           "recent": [], "recent_count": 0, "world_writable": 0, "wordpress": [], "truncated": False}
    cutoff = time.time() - recent_days * 86400
    for root in roots:
        if not os.path.isdir(root):
            continue
        res["roots"].append(root)
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in ("node_modules", ".git", "cache")]
            try:
                if os.stat(d).st_mode & stat.S_IWOTH:
                    res["world_writable"] += 1
            except OSError:
                pass
            if "wp-config.php" in files:
                res["wordpress"].append(wordpress_info(d))
            for name in files:
                if res["files_scanned"] >= max_files:
                    res["truncated"] = True
                    break
                path = os.path.join(d, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                res["files_scanned"] += 1
                if st.st_mode & stat.S_IWOTH:
                    res["world_writable"] += 1
                if st.st_mtime > cutoff:
                    res["recent_count"] += 1
                    if len(res["recent"]) < 25:
                        res["recent"].append({"file": path, "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))})
                low = name.lower()
                if "/wp-content/uploads/" in path.replace("\\", "/") and low.endswith(PHP_EXT) and low != "index.php":
                    res["php_in_uploads"].append(path)
                if low.endswith(PHP_EXT) and st.st_size < 3_000_000:
                    try:
                        with open(path, "rb") as fh:
                            m = WEBSHELL.search(fh.read())
                    except OSError:
                        m = None
                    if m:
                        res["suspicious"].append({"file": path, "match": m.group(0)[:80].decode("latin-1")})
    for s in res["suspicious"]:
        add("high", "Web", "Possible web shell / malware: %s" % s["file"],
            "Matched pattern: %s" % s["match"],
            "Compare with a clean copy (e.g. official WordPress/plugin files). Remove it if it is not part of your code, then change all passwords.")
    for f in res["php_in_uploads"]:
        add("high", "Web", "PHP file inside the uploads folder: %s" % f,
            "WordPress never puts PHP files in uploads; this is how most uploaded web shells look.",
            "Check and delete it, and block PHP in uploads (web_hardening role does this).")
    if res["world_writable"]:
        add("medium", "Web", "%d world-writable file(s)/folder(s) in the web folders" % res["world_writable"],
            "Any local user or compromised process can change these files.",
            "Set files to 644 and folders to 755 (web_hardening role does this).")
    if res["truncated"]:
        add("info", "Web", "Web scan stopped after %d files" % max_files, "", "Raise security_scan_max_files to scan everything.")
    return res


def wordpress_info(path):
    cfg = read(os.path.join(path, "wp-config.php"))
    ver = re.search(r"\$wp_version\s*=\s*'([^']+)'", read(os.path.join(path, "wp-includes/version.php")))
    try:
        mode = oct(os.stat(os.path.join(path, "wp-config.php")).st_mode & 0o777)[2:]
    except OSError:
        mode = "?"
    info = {"path": path, "version": ver.group(1) if ver else "?", "wp_config_mode": mode,
            "file_edit_disabled": bool(re.search(r"DISALLOW_FILE_EDIT['\"]\s*,\s*true", cfg, re.I)),
            "debug_on": bool(re.search(r"WP_DEBUG['\"]\s*,\s*true", cfg, re.I))}
    if not info["file_edit_disabled"]:
        add("medium", "WordPress", "Theme/plugin editor is enabled in %s" % path,
            "If an admin account is stolen, the attacker can write PHP code from the dashboard.",
            "Add define('DISALLOW_FILE_EDIT', true); to wp-config.php (web_hardening role does this).")
    if info["debug_on"]:
        add("medium", "WordPress", "WP_DEBUG is on in %s" % path,
            "Error messages can leak file paths and database details to visitors.",
            "Set WP_DEBUG to false on production.")
    if mode not in ("600", "640", "440", "400"):
        add("medium", "WordPress", "wp-config.php is readable by everyone (mode %s) in %s" % (mode, path),
            "It contains the database password.",
            "chmod 640 and make the web user the owner or group.")
    return info


def http_headers():
    try:
        req = urllib.request.Request("http://127.0.0.1/", method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as r:
            h = dict(r.headers)
    except urllib.error.HTTPError as e:
        h = dict(e.headers)
    except Exception:  # noqa: BLE001 - no web server is a valid result
        return None
    server = h.get("Server", "")
    out = {"server": server,
           "x_frame_options": h.get("X-Frame-Options"),
           "x_content_type_options": h.get("X-Content-Type-Options"),
           "referrer_policy": h.get("Referrer-Policy")}
    if re.search(r"\d", server):
        add("low", "Web", "Web server shows its version: '%s'" % server,
            "Attackers use the exact version to pick known exploits.",
            "nginx: server_tokens off; Apache: ServerTokens Prod (web_hardening role does this).")
    missing = [k for k in ("x_frame_options", "x_content_type_options") if not out[k]]
    if missing:
        add("low", "Web", "Missing security headers: %s" % ", ".join(missing),
            "They protect visitors against clickjacking and content-type tricks.",
            "Add them in the web server config (web_hardening role does this).")
    return out


# ---------------------------------------------------------------- hardening state
def hardening_state(family, firewall):
    st = {}
    rc, out = run(["sshd", "-T"])
    if rc != 0:
        rc, out = run(["/usr/sbin/sshd", "-T"])
    cfg = dict(line.split(None, 1) for line in out.splitlines() if " " in line)
    st["ssh_running"] = rc == 0
    st["ssh_port"] = cfg.get("port", "?")
    st["ssh_root_login"] = cfg.get("permitrootlogin", "?")
    st["ssh_password_auth"] = cfg.get("passwordauthentication", "?")
    st["ssh_max_auth_tries"] = cfg.get("maxauthtries", "?")
    if st["ssh_running"]:
        if st["ssh_root_login"] in ("yes",):
            add("high", "SSH", "root can log in over SSH with a password",
                "Bots try root passwords on every server all day long.",
                "Set 'PermitRootLogin no' (hardening role does this).")
        elif st["ssh_root_login"] not in ("no",):
            add("low", "SSH", "root can log in over SSH with a key (%s)" % st["ssh_root_login"],
                "Safer than a password, but a normal user + sudo leaves a clearer audit trail.",
                "Set 'PermitRootLogin no' once you have a sudo user.")
        if st["ssh_password_auth"] == "yes":
            add("medium", "SSH", "SSH accepts passwords",
                "Passwords can be guessed by brute force; keys cannot.",
                "Install an SSH key for your admin user, then set 'PasswordAuthentication no'.")
        try:
            if int(st["ssh_max_auth_tries"]) > 4:
                add("low", "SSH", "SSH allows %s password tries per connection" % st["ssh_max_auth_tries"],
                    "", "Set 'MaxAuthTries 3'.")
        except ValueError:
            pass

    st["firewall"] = firewall
    if st["firewall"] == "none":
        add("high", "Firewall", "No active firewall found",
            "Every service that listens on the network is reachable from the internet.",
            "Turn on UFW / firewalld and only open SSH, HTTP and HTTPS (hardening role does this).")

    rc, out = run(["fail2ban-client", "status", "sshd"])
    st["fail2ban"] = rc == 0
    m = re.search(r"Total banned:\s*(\d+)", out)
    st["fail2ban_total_banned"] = int(m.group(1)) if m else None
    if not st["fail2ban"]:
        add("medium", "SSH", "No brute-force protection (Fail2ban) on SSH",
            "Password-guessing bots can try forever.",
            "Install Fail2ban with an sshd jail (hardening role does this).")

    rc, out = run(["getenforce"])
    if rc == 0:
        st["mac"] = "SELinux " + out.strip()
        if out.strip() != "Enforcing":
            add("medium", "System", "SELinux is %s" % out.strip(),
                "SELinux limits what a hacked service can do.",
                "Set SELINUX=enforcing in /etc/selinux/config and reboot (after testing).")
    else:
        rc, out = run(["aa-enabled"])
        st["mac"] = "AppArmor " + ("enabled" if out.strip() == "Yes" else "disabled")
        if out.strip() != "Yes" and family == "debian":
            add("low", "System", "AppArmor is not enabled", "", "Enable AppArmor.")

    if family == "debian":
        st["auto_updates"] = 'Unattended-Upgrade "1"' in read("/etc/apt/apt.conf.d/20auto-upgrades")
        rc, out = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120)
        lines = [ln for ln in out.splitlines() if ln.startswith("Inst ")]
        st["pending_updates"] = len(lines)
        st["pending_security_updates"] = sum(1 for ln in lines if "-security" in ln)
        st["reboot_required"] = os.path.exists("/var/run/reboot-required")
    else:
        rc, out = run(["systemctl", "is-enabled", "dnf-automatic.timer"])
        st["auto_updates"] = out.strip() == "enabled"
        rc, out = run(["dnf", "-q", "--cacheonly", "updateinfo", "list", "--security"], timeout=120)
        st["pending_security_updates"] = len([ln for ln in out.splitlines() if ln.strip()]) if rc == 0 else None
        rc, out = run(["dnf", "-q", "--cacheonly", "check-update"], timeout=120)
        st["pending_updates"] = len([ln for ln in out.splitlines() if re.match(r"^\S+\.\S+\s+\S+\s+\S+", ln)]) if rc in (0, 100) else None
        rc, out = run(["needs-restarting", "-r"])
        st["reboot_required"] = rc == 1
    if not st["auto_updates"]:
        add("medium", "Updates", "Automatic security updates are off",
            "Security patches wait until someone remembers to install them.",
            "Turn on unattended-upgrades / dnf-automatic for security updates (hardening role does this).")
    if st.get("pending_security_updates"):
        add("high", "Updates", "%s security update(s) waiting to be installed" % st["pending_security_updates"],
            "Known vulnerabilities stay open until they are installed.",
            "Install them ('apt upgrade' / 'dnf upgrade --security') in a maintenance window.")
    if st.get("reboot_required"):
        add("low", "Updates", "A reboot is needed to finish updates",
            "The new kernel or libraries are not active yet.", "Reboot in a maintenance window.")

    m = re.search(r"hardening_index=(\d+)", read("/var/log/lynis-report.dat"))
    st["lynis_index"] = int(m.group(1)) if m else None
    return st


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--web-roots", nargs="*", default=["/var/www"])
    ap.add_argument("--recent-days", type=int, default=7)
    ap.add_argument("--max-files", type=int, default=50000)
    a = ap.parse_args()

    info = system_info()
    fw = firewall_active()
    data = {
        "system": info,
        "listening_ports": listening_ports(fw),
        "accounts": accounts(),
        "cron_jobs": cron_jobs(),
        "local_services": systemd_units(),
        "suspicious_processes": processes(),
        "suid": suid_files(),
        "web": web_scan(a.web_roots, a.recent_days, a.max_files),
        "http": http_headers(),
        "hardening": hardening_state(info["os_family"], fw),
    }
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    data["findings"] = sorted(FINDINGS, key=lambda f: order[f["severity"]])
    data["counts"] = {k: sum(1 for f in FINDINGS if f["severity"] == k) for k in order}
    print(json.dumps(data))


if __name__ == "__main__":
    main()
