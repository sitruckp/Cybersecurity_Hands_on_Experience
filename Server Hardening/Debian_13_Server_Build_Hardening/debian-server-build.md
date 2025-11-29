# Debian 13 Server Baseline
**Asset Name**: REDACTED-HOST (Debian 13)  
**Classification**: Internal (configs/logs; potential confidential auth data—encrypt backups)  
**Owner**: Kevin (SOC Lab Analyst)  
**Scan Date**: 2025-11-13  
**Lynis Hardening Index**: 86/100 (Post-Week 1 mitigations: libpam-tmpdir, apt-listbugs)  
**NIST Tie-In**: SP 800-60 Vol. 2 (Data Classification); CM-8 (System Component Inventory)  

## Asset Overview
- **Hardware/VM**: HP 14 laptop VM (isolated lab; bridged net REDACTED)  
- **OS Version**: Debian 13 (kernel 6.12.48+deb13)  
- **Key Services**: SSH (Port 2222, key auth), UFW Firewall (DENY incoming), Unattended-Upgrades (auto-security)  
- **Data Types**: Logs (Internal), Configs (Confidential—e.g., SSH keys), Temp Files (Public—/tmp hardened)  

## Inventory Table (Ports/Services/Files)
| Asset Component | Description | Classification | Risk Score (Likelihood x Impact) | Mitigation/Control | Status |
|-----------------|-------------|----------------|----------------------------------|--------------------|--------|
| SSH Service (Port 2222/tcp) | OpenSSH daemon for remote access | Confidential (auth keys) | 4x5=20 (brute-force exfil) | Key-based auth only; UFW ALLOW from lab net; fail2ban pending | Active |
| UFW Firewall (/etc/ufw/ufw.conf) | Host-based firewall with DENY default | Internal (ruleset) | 3x4=12 (misconfig exposure) | Logging enabled; reviewed weekly | Active |
| Sysctl Kernel Hardening (/etc/sysctl.conf) | Params like net.ipv4.ip_forward=0 | Internal (system params) | 2x3=6 (DoS amplification) | Applied via sysctl -p; reboot persistent | Active |
| Lynis Log (/var/log/lynis.log) | Audit trail (86/100 score) | Confidential (vuln details) | 3x4=12 (leak = recon aid) | Chown kevin:kevin; encrypt backups (openssl) | Active |
| /tmp Directory | Temp files (PAM-hardened) | Public (no persistence) | 2x2=4 (race conditions) | Noexec/nosuid via mount; libpam-tmpdir installed | Active |

## Compliance Mapping (NIST SP 800-53)
- **SC-28**: Protection of Information at Rest → Encrypt Lynis log backups (openssl aes-256).  
- **CM-8**: System Component Inventory → This doc + ss/systemctl scans.  
- **AC-3**: Access Enforcement → Non-root user (kevin), sudoers limited.  

## Next Steps
- **Encryption Test**: Encrypt sample config (e.g., `openssl enc -aes-256-cbc -in sshd_config -out sshd_config.enc`).  
- **Audit Frequency**: Weekly Lynis re-run; update table.  
- **Incident Tie-In**: If breach, classify as "Server Asset Compromise" (High impact).  

**Analyst Notes**: Baseline from Week 1 risks (e.g., weak ciphers mitigated). Ties to Google cert: Asset tagging for IR scoping. Update on changes (e.g., new service = add row).
