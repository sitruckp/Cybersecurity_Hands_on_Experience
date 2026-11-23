# Lab Server Hardening – Lynis Baseline & Improvements

**Date**: 2026-11-23  
**System**: Ubuntu Server 24.04.5 LTS  
**Hostname**: labserver  
**Hardware**: Lenovo ThinkPad E520 (12 GB RAM)  
**Tool**: Lynis 3.1.7  

## Baseline (Before Changes)

| Metric              | Value |
|---------------------|-------|
| Hardening Index     | 70    |
| Warnings            | 0     |
| Notable gaps        | SSH options loose, password aging not configured, basic sysctl not set, sudoers.d permissions, default SSH port 22 |

## Changes Applied

### 1. SSH Hardening (`/etc/ssh/sshd_config`)
```
Port 2222
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 2
X11Forwarding no
AllowAgentForwarding no
ClientAliveCountMax 2
LogLevel VERBOSE
TCPKeepAlive no
```
Config tested with `sshd -t` and reloaded/restarted.  
UFW updated to allow 2222/tcp and the default OpenSSH (port 22) rule was removed.

### 2. Password Aging (`/etc/login.defs` + `chage`)
```
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
```
Applied to user `kevin` and `root`.

### 3. Kernel Sysctl (`/etc/sysctl.d/99-hardening.conf`)
```
kernel.kptr_restrict = 2
net.ipv4.conf.all.log_martians = 1
```

### 4. Default umask
Set to `027` in:
- `/etc/login.defs`
- `/etc/profile`
- `/etc/bash.bashrc`

### 5. Permissions
- `/etc/sudoers.d` set to `750` root:root

### 6. Unused Network Protocols
Blacklisted in `/etc/modprobe.d/disable-unused-protocols.conf`:
```
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
```
Initramfs updated.

### 7. Fail2ban
Created `/etc/fail2ban/jail.local`:
```ini
[sshd]
enabled = true
port = 2222
backend = systemd
```
Jail is active and monitoring the new SSH port.

### 8. Automation
- Created `/usr/local/bin/lab-vuln-updates.sh`
  - Updates Nuclei templates
  - Updates Trivy vulnerability database
  - Runs light local Nuclei scan (critical/high only)
- Added to root crontab (Sunday 02:00):
  ```
  0 2 * * 0 /usr/local/bin/lab-vuln-updates.sh
  ```

## Results (After Changes)

| Metric              | Value |
|---------------------|-------|
| Hardening Index     | **80** |
| Warnings            | 0     |
| SSH Port            | 2222 (OK) |
| SSH controls        | All targeted options OK |
| Password aging      | Configured |
| umask               | 027 (OK) |
| Sysctl tweaks       | Active |
| Fail2ban            | Enabled on port 2222 |

**Improvement**: +10 points on the Lynis hardening index with low-risk, reversible changes.

## Remaining Optional Items (Not Applied)
- GRUB bootloader password
- Separate partitions for `/home`, `/tmp`, `/var`
- Password hashing rounds / PAM strength modules
- Compiler restrictions
- Additional sysctl values
- External log shipping

These were deferred as higher effort or lower practical value for a home lab.

## Tools Used
- Lynis (system hardening audit)
- Nuclei (template-based vulnerability scanner)
- Trivy (container/OS vulnerability scanner)
- Fail2ban
- UFW
- Standard Ubuntu packages (`sshd`, `sysctl`, `chage`)

## Notes
All changes were applied on a constrained 12 GB RAM lab system. Docker is used for Nuclei and Trivy to keep the host clean. The Sunday cron job keeps vulnerability data current without heavy resource use. SSH was moved off the default port while existing sessions remained intact during the change.

---
*Documented for portfolio purposes – open-source home lab, blue-team focus.*
