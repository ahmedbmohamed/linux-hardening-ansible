# linux-hardening-ansible

![CI](https://github.com/ahmedbmohamed/linux-hardening-ansible/actions/workflows/ci.yml/badge.svg)

Ansible roles that **secure Linux servers and prove it**, for **RHEL / Rocky Linux / AlmaLinux 9** and **Ubuntu 22.04 / 24.04 / Debian 12**:

| Role | What it does | Changes the server? |
|---|---|---|
| [`hardening`](#what-the-hardening-role-does) | SSH, firewall, Fail2ban, automatic security updates, kernel settings, audit logs | Yes |
| [`web_hardening`](#web-server-and-wordpress-hardening) | Nginx / Apache and WordPress lock-down | Yes (config tested, rolled back on error) |
| [`security_scan`](#security-scan-and-client-report) | Finds web shells, backdoors, suspicious cron jobs and services, open ports, risky accounts, missing updates, and writes a **client-ready report** | **No, read-only** |

Plus a **Lynis audit before and after** to measure the result.

Built by Ahmed Ben Mohamed, Red Hat Certified Engineer (RHCE).

## What the hardening role does

| Area | RHEL family | Debian family |
|---|---|---|
| SSH | Key-only login (when a key is given), no root login, max 3 tries, modern ciphers, idle timeout, banner, custom port + SELinux port label | Same, plus `ssh.socket` handling on Ubuntu 24.04 |
| Firewall | firewalld: only SSH + chosen ports, cockpit closed | UFW: deny incoming, allow outgoing, only SSH + chosen ports |
| Brute-force protection | Fail2ban (SSH jail, firewalld ban action) | Fail2ban (SSH jail, UFW ban action) |
| Security updates | dnf-automatic, security updates only | unattended-upgrades, optional auto reboot time |
| Kernel / network | sysctl: no redirects or source routing, SYN cookies, martian logging, kptr/dmesg restrictions, ptrace scope | Same |
| Audit logging | auditd + rules on users, sudoers, SSH config | Same |
| MAC | Warns if SELinux is not enforcing | Warns if AppArmor is off |
| Cleanup | Removes telnet, rsh, talk, ypbind | Same |

### Safety features

- **No lockout**: password login is only turned off when an admin SSH key is installed. The SSH port is opened in the firewall *before* the firewall is turned on.
- **Config tested before restart**: `sshd -t` must pass before SSH is restarted.
- **Idempotent**: a second run changes nothing (checked in CI).
- **SELinux is never switched off**, and never switched on automatically (that needs a relabel + reboot). It is reported instead.

## Web server and WordPress hardening

`playbooks/web.yml` (role `web_hardening`) finds Nginx / Apache and every WordPress site under `/var/www`, then:

| Area | What is done |
|---|---|
| Web server | Hides the version (`server_tokens off` / `ServerTokens Prod`), adds security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), no directory listing, hidden files (`.git`, `.env`) blocked |
| WordPress | **PHP blocked in `wp-content/uploads`** (stops uploaded web shells), `xmlrpc.php` blocked, `wp-config.php`, `readme.html`, `.sql/.bak/.log` files blocked |
| Files | Folders 755, files 644, `wp-config.php` 640 (only when it belongs to the web user, so the site keeps working) |
| wp-config.php | `DISALLOW_FILE_EDIT` (no code editor in wp-admin) |

**Safety:** the web server config is tested **before** any change (`nginx -t` / `apachectl configtest`). If it already fails, nothing is touched. If it fails **after** the changes, they are removed automatically and the web server is **not** reloaded.

## Security scan and client report

`playbooks/scan.yml` (role `security_scan`) is **read-only**. It writes `reports/<host>-<label>-security-report.md` (and the raw JSON) with:

- **Summary** by severity (high / medium / low) and an overall verdict
- **Checklist**: SSH, firewall, Fail2ban, automatic updates, pending security updates, SELinux/AppArmor, extra root accounts, empty passwords, suspicious processes, web shells
- **Findings**, each with *what we found*, *why it matters* and *how to fix it*
- **Backdoor hunting**: suspicious cron jobs and systemd services (download-and-run, `/tmp` and `/dev/shm`, reverse shells), crypto-miners, programs running from temp folders or only from memory, SUID files in unusual places
- **Website scan**: web shell patterns (`eval(base64_decode(...))`, `system($_POST...)`, known shells), PHP files in uploads, world-writable files, recently changed files, WordPress version / debug / file-editor status
- **Inventory**: listening ports, users who can log in, SSH keys, sudo rules, HTTP security headers

Malware is **reported, never deleted automatically**: removing files from a client's site is a decision for a human.

### Try it on a demo "hacked" site

`tests/demo-site.sh` creates a fake WordPress site with a planted (harmless) web shell and cron job:

```bash
sudo bash tests/demo-site.sh                                   # needs nginx installed
ansible-playbook playbooks/scan.yml -e security_scan_label=before -K
ansible-playbook playbooks/web.yml -K
ansible-playbook playbooks/scan.yml -e security_scan_label=after -K
sudo bash tests/demo-site.sh --remove                          # clean up
```

The scan finds the web shell, the PHP file in uploads and the cron job; after `web.yml`, `xmlrpc.php`, `wp-config.php` and the shell return **403** while the site still works.

**Result on an Ubuntu 22.04 VM (VMware), demo site:**

| | High | Medium | Low |
|---|---|---|---|
| Scan before | 4 | 11 | 2 |
| Scan after `web.yml` | 4 | **6** | **0** |

| URL | Before | After |
|---|---|---|
| `/` (site) | 200 | **200** (still works) |
| `/xmlrpc.php` | 200 | **403** |
| `/wp-config.php` | 200 | **403** |
| `/wp-content/uploads/.../image.php` (planted shell) | 200 | **403** |
| `Server` header | `nginx/1.18.0 (Ubuntu)` | **`nginx`** (version hidden) |

Second run of `web.yml`: `changed=0`. The 4 high findings left are on purpose: the planted shell, the PHP file in uploads and the cron job are **reported for a human to remove**, and the pending security updates were being installed by unattended-upgrades.

## Results

Measured on two lab VMs (VMware), default role settings, no SSH key given (so password login stays on):

| Host | Lynis version | Hardening index | Warnings | Suggestions |
|---|---|---|---|---|
| RHEL 9.4, before | 3.1.7 (EPEL) | 67 | 2 | 40 |
| **RHEL 9.4, after** | | **78 (+11)** | **1** | **32** |
| Ubuntu 22.04, before | 3.0.x (Ubuntu repo) | 60 | 2 | 52 |
| **Ubuntu 22.04, after** | | **69 (+9)** | **1** | **44** |

Second run of the role on both hosts: `changed=0` (idempotent).
Compare before vs after on the same host only: the two systems use different Lynis versions.

Full reports: `reports/` (created by `playbooks/audit.yml`).

## Quick start: test lab on your PC (Windows, macOS or Linux)

Needs [VirtualBox](https://www.virtualbox.org/) and [Vagrant](https://developer.hashicorp.com/vagrant). About 2 GB of free RAM. Ansible runs inside the VMs, so you do not need Ansible on Windows.

```bash
vagrant up --provision-with audit_before       # 2 VMs + Lynis score "before"
vagrant provision --provision-with harden      # apply the role
vagrant provision --provision-with audit_after # Lynis score "after"
```

Scores are written to `reports/*-summary.txt`.

## Use on real servers

```bash
pip install ansible-core
cp inventory/hosts.example.ini inventory/hosts.ini   # add your servers
nano inventory/group_vars/all.yml                    # paste your public key

ansible-playbook playbooks/scan.yml -e security_scan_label=before   # read-only report
ansible-playbook playbooks/audit.yml -e audit_label=before            # Lynis score
ansible-playbook playbooks/site.yml                                   # system hardening
ansible-playbook playbooks/web.yml                                    # web server + WordPress
ansible-playbook playbooks/audit.yml -e audit_label=after
ansible-playbook playbooks/scan.yml -e security_scan_label=after
```

Run only one part with tags: `--tags ssh`, `firewall`, `fail2ban`, `updates`, `sysctl`, `audit`.

> If you change `hardening_ssh_port`, update `ansible_port` in your inventory before the next run.

## Main variables

| Variable | Default | Meaning |
|---|---|---|
| `hardening_admin_user` | `deploy` | Sudo user to create |
| `hardening_admin_pubkey` | `""` | Its SSH public key. When set, password login is turned off |
| `hardening_ssh_port` | `22` | SSH port |
| `hardening_ssh_allow_users` | `[]` | Limit SSH to these users |
| `hardening_firewall_allowed_tcp_ports` | `[80, 443]` | Extra open ports |
| `hardening_fail2ban_bantime` | `1h` | Ban time |
| `hardening_auto_reboot_time` | `""` | e.g. `"03:30"` (Debian family) |
| `hardening_firewall`, `hardening_fail2ban`, `hardening_auto_updates`, `hardening_sysctl`, `hardening_auditd` | `true` | Turn a part on or off |

All options: [`hardening`](roles/hardening/defaults/main.yml), [`web_hardening`](roles/web_hardening/defaults/main.yml), [`security_scan`](roles/security_scan/defaults/main.yml).

## CI

GitHub Actions runs on every push:
1. `ansible-lint` (production profile)
2. Ubuntu 24.04: audit before, harden, **idempotence check**, audit after
3. Rocky Linux 9 container: harden + idempotence check
4. Web: Nginx + demo "hacked" WordPress site, scan must find the planted web shell and cron job, web hardening, **blocked URLs must return 403 while the site returns 200**, idempotence, scan after

## License

MIT
