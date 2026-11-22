# linux-hardening-ansible

![CI](https://github.com/ahmedbmohamed/linux-hardening-ansible/actions/workflows/ci.yml/badge.svg)

One Ansible role that applies a security baseline to **RHEL / Rocky Linux / AlmaLinux 9** and **Ubuntu 22.04 / 24.04 / Debian 12** servers, then proves the result with a **Lynis audit before and after**.

Built by Ahmed Ben Mohamed, Red Hat Certified Engineer (RHCE).

## What it does

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

## Results

Measured with Lynis 3.1.7 on a RHEL 9.4 VM (VMware), default role settings, no SSH key given (so password login stays on):

| Host | Lynis hardening index | Warnings | Suggestions |
|---|---|---|---|
| RHEL 9.4, before | 67 | 2 | 40 |
| **RHEL 9.4, after** | **78** | **1** | **32** |
| Ubuntu 22.04 | _coming soon_ | | |

Second run of the role on the same host: `changed=0` (idempotent).

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

ansible-playbook playbooks/audit.yml -e audit_label=before
ansible-playbook playbooks/site.yml
ansible-playbook playbooks/audit.yml -e audit_label=after
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

All options: [`roles/hardening/defaults/main.yml`](roles/hardening/defaults/main.yml).

## CI

GitHub Actions runs on every push:
1. `ansible-lint` (production profile)
2. Ubuntu 24.04: audit before, harden, **idempotence check**, audit after
3. Rocky Linux 9 container: harden + idempotence check

## License

MIT
