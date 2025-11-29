# Debian Server Hardening Log - November 16, 2025

## Overview
Today's session focused on troubleshooting Apache2 startup issues after ModSecurity configs, purging and reinstalling to reset, and addressing lingering Lynis suggestions. We hit a high of 88 hardening index earlier, dipped to 84 post-reboot (recalibration artifact), but suggestions dropped to 19—no warnings. Key gains: AIDE checksum upgraded, USB/firewire blacklisted, sysctl reapplied. AppArmor on Apache started, but Postgres next for Metasploit DB confinement. No major breaks; server stable, Postgres/SSH up.

## Progress Summary
- **Starting Index**: 83 (initial scans).
- **Peak**: 88 (after kernel/Apache fixes).
- **Post-Reboot**: 84 (new suggestions like PROC-3612, but fewer overall).
- **Suggestions**: Down to 19 from 20+ (cleared USB-1000, STRG-1846, FINT-4402).
- **Wins**: Auditd tuned (no floods), AIDE DB initialized, Ansible installed for automation.

| Category | Before | After | Notes |
|----------|--------|-------|-------|
| Kernel Hardening (KRNL-6000) | 12 DIFFERENT | Cleared | Reapplied sysctl -p post-reboot. |
| Storage Disable (USB/STRG) | Suggestions | Cleared | Blacklisted usb-storage/firewire-ohci. |
| AIDE Checksum (FINT-4402) | MD5 | SHA512 | Sed replace and init DB. |
| Deleted Files (LOGG-2190) | Postgres/Apache | Postgres only | Apache restart pending; ignore or restart DB. |
| Unconfined Processes | 35 | 32 (Apache enforced) | Genprof/enforce on Apache; Postgres next. |

## Fixes Implemented
### Critical
1. Sysctl Reapply (KRNL-6000):  
   ```
   sudo sysctl -p
   ```
   Verification: `sudo sysctl -a | grep kptr_restrict` (=2).

2. Protocols Unload (NETW-3200):  
   ```
   sudo modprobe -r dccp sctp rds tipc
   ```
   Verification: `lsmod | grep -E 'dccp|sctp|rds|tipc'` (empty).

3. UFW Clean (FIRE-4513):  
   ```
   sudo ufw status numbered verbose
   sudo ufw delete <num>  # Low-traffic lines
   sudo ufw reload
   ```
   Verification: `sudo ufw status verbose` (minimal rules).

4. Deleted Files (LOGG-2190):  
   ```
   sudo lsof +L1
   sudo systemctl restart postgresql@17-main
   ```
   Verification: `sudo lsof +L1` (empty after).

### Easy
5. Lynis Update (LYNIS): No newer version—skipped Git pull for now.

6. debsums Cron (PKGS-7370):  
   ```
   sudo crontab -e
   ```
   Added: `@daily /usr/bin/debsums --changed > /var/log/debsums.log`.  
   Verification: `sudo crontab -l | grep debsums`.

7. USB/Firewire (USB-1000, STRG-1846):  
   ```
   sudo tee -a /etc/modprobe.d/blacklist.conf << EOF
   blacklist usb-storage
   blacklist firewire-ohci
   EOF
   sudo update-initramfs -u
   ```
   Verification: `lsmod | grep usb_storage` (empty).

8. AIDE Checksum (FINT-4402):  
   ```
   sudo sed -i 's/MD5/SHA512/g' /etc/aide/aide.conf
   sudo aide --init --config /etc/aide/aide.conf
   sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
   ```
   Verification: `grep SHA512 /etc/aide/aide.conf`.

9. Automation (TOOL-5002): Ansible installed—rerun Lynis detects.

10. Home Dirs (HOME-9304):  
    ```
    sudo chmod 700 /home/kevin
    ```
    Verification: `ls -ld /home/kevin` (drwx------).

### AppArmor
11. Unconfined Cleanup:  
    ```
    sudo aa-genprof /usr/lib/postgresql/17/bin/postgres
    psql -U postgres -c "SELECT 1;"  # Test DB
    sudo aa-logprof
    sudo aa-enforce /etc/apparmor.d/usr.lib.postgresql.17.bin.postgres
    sudo systemctl reload apparmor
    ```
    Verification: `sudo aa-status` (fewer unconfined).

## Apache Troubleshooting Log
- Issue: Permission denied on apache2.conf post-reinstall.
- Fixes Tried: Recursive perms, chown/chmod—still failing (AppArmor or deep dir issue).
- Recommendation: Purge/reinstall worked initially, but if persists, disable Apache (not core to labs): `sudo systemctl disable apache2`—ignore HTTP suggestions, or check AppArmor denials: `sudo aa-complain /usr/sbin/apache2`; reload apparmor, restart.

## Next Steps
- Rerun Lynis: `sudo lynis audit system`—share if stalls (aim 90+).
- Metasploit Hardening: Create msfuser, install under non-root, confine with aa-genprof.