# Lab Server Hardening – Lynis Baseline & Improvements

**Date**: 2026-11-22  
**System**: Ubuntu Server 24.04.5 LTS  
**Hostname**: labserver  
**Hardware**: Lenovo ThinkPad E520 (12 GB RAM)  
**Tool**: Lynis 3.1.7  

## Baseline (Before Changes)

| Metric              | Value |
|---------------------|-------|
| Hardening Index     | 70    |
| Warnings            | 0     |
| Notable gaps        | SSH options loose, password aging not configured, basic sysctl not set, sudoers.d permissions |

## Changes Applied

### 1. SSH Hardening (`/etc/ssh/sshd_config`)
```
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 2
X11Forwarding no
AllowAgentForwarding no
ClientAliveCountMax 2
LogLevel VERBOSE
TCPKeepAlive no
```
Config tested with `sshd -t` and reloaded with `systemctl reload ssh`. Port left at 22 intentionally.

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

### 4. Permissions
- `/etc/sudoers.d` set to `750` root:root

### 5. Automation
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
| Hardening Index     | **78** |
| Warnings            | 0     |
| SSH controls        | All targeted options now OK |
| Password aging      | Configured |
| Sysctl tweaks       | Active |

**Improvement**: +8 points on the Lynis hardening index with low-risk, reversible changes.

## Remaining Optional Items (Not Applied)
- Change SSH port (left at 22 for simplicity)
- GRUB bootloader password
- Separate partitions for `/home`, `/tmp`, `/var`
- Stricter default umask
- Compiler restrictions
- Additional sysctl values

These were deferred as higher effort or lower practical value for a home lab.

## Tools Used
- Lynis (system hardening audit)
- Nuclei (template-based vulnerability scanner)
- Trivy (container/OS vulnerability scanner)
- Standard Ubuntu packages (`sshd`, `sysctl`, `chage`)

## Notes
All changes were applied on a constrained 12 GB RAM lab system. Docker is used for Nuclei and Trivy to keep the host clean. The Sunday cron job keeps vulnerability data current without heavy resource use.

---
*Documented for portfolio purposes – open-source home lab, blue-team focus.*
