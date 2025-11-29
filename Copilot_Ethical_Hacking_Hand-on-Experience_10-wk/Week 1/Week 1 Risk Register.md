# Risk Register – Debian 13 Lab Server
Date: 2025-11-14
Owner: kevin@lab-server
Hardening Index: 85/100 (Lynis)

| Risk ID | Description                                      | Likelihood | Impact | Risk Rating | Current Control(s)                | Recommended Mitigation |
|---------|--------------------------------------------------|------------|--------|-------------|-----------------------------------|------------------------|
| R1      | Fail2ban jails disabled – SSH brute force risk   | High       | High   | CRITICAL    | UFW active, SSH on port 2222      | Enable fail2ban jails; configure sshd jail for port 2222 |
| R2      | Outdated release (>4 months) – patch gap         | Medium     | High   | HIGH        | Unattended-upgrades enabled       | Verify repos; run `apt upgrade`; schedule monthly patch review |
| R3      | No auditd/process accounting – limited visibility| Medium     | Medium | MEDIUM      | rsyslog enabled                   | Install & configure `auditd` and `acct`; enable sysstat |
| R4      | Insecure/unused protocols (dccp, sctp, etc.)     | Low        | Medium | LOW         | UFW deny incoming by default      | Disable protocols via `/etc/modprobe.d/blacklist.conf` |
| R5      | Home/var not on separate partitions – DoS risk   | Medium     | Medium | MEDIUM      | Default filesystem layout         | Plan partitioning; monitor disk usage with alerts |
| R6      | Weak file/home dir permissions                   | Medium     | Medium | MEDIUM      | Basic chmod defaults              | Audit with `find /home -type d -ls`; tighten permissions |
| R7      | Compilers accessible – potential local privilege | Low        | Medium | LOW         | Non-root user enforced            | Restrict compiler access to root; remove if unnecessary |
| R8      | iptables rules unused – possible misconfig       | Low        | Medium | LOW         | UFW front-end                     | Review with `iptables -L --line-numbers`; prune unused rules |
| R9      | Deleted files in use – forensic blind spot       | Low        | Low    | LOW         | rsyslog basic logging             | Investigate with `lsof`; enable log rotation monitoring |



# Risk Register – Kali Linux Workstation
Date: 2025-11-14
Owner: kevin@kali-lab
Source: Lynis audit + Nmap scan
Hardening Index: 64/100 (Lynis)

| Risk ID | Finding Code | Risk Description | Likelihood | Impact | Risk Rating | Recommended Action |
|---------|--------------|------------------|------------|--------|-------------|--------------------|
| R01     | FIRE-4512    | No active firewall; SSH (2222/tcp) exposed with no packet filtering. | High | High | CRITICAL | Install and enable ufw; set default deny incoming; allow only required ports. |
| R02     | DBS-1828     | PostgreSQL config files world-readable; potential leakage of sensitive paths/keys. | High | High | CRITICAL | Restrict permissions (`chmod 600`); ensure only root/service owner access. |
| R03     | DEB-0880     | No brute-force protection; SSH vulnerable to unlimited credential guessing. | High | Medium | HIGH | Install fail2ban; configure SSH jail with aggressive lockout thresholds. |
| R04     | BOOT-5122    | GRUB bootloader unsecured; physical attacker could gain root via single-user mode. | Low | High | MEDIUM | Set GRUB password in `/etc/default/grub`; regenerate config. |
| R05     | SSH-7408     | Weak SSH configuration (AllowTcpForwarding, X11Forwarding, high MaxAuthTries). | Medium | Medium | MEDIUM | Harden `/etc/ssh/sshd_config`; disable forwarding; reduce auth attempts; set verbose logging. |
| R06     | NETW-2705    | Single nameserver configured; DNS resolution fragile, risk of downtime. | Medium | Low | LOW | Add secondary DNS (e.g., 8.8.8.8) in `/etc/resolv.conf` or network manager. |
| R07     | AUTH-9262/9286 | Weak password policy; no complexity enforcement or expiration. | High | Medium | HIGH | Install PAM modules (libpam-passwdqc); enforce complexity; set password aging in `/etc/login.defs`. |
| R08     | ACCT-9628    | Audit logging disabled; no forensic trail if compromised. | Low | High | MEDIUM | Install and enable `auditd`; configure rules for critical binaries and configs. |
