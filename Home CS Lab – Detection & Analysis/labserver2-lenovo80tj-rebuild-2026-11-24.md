# labserver2 Rebuild Log – Lenovo 80TJ

**Date:** 2026-11-24  
**Machine:** Lenovo 80TJ (AMD A6-7310, 8 GB RAM)  
**Role:** Secondary Suricata sensor  
**Operator:** kevin  
**Previous hardware:** HP Laptop 17-by1xxx (retired from this role)

---

## Objective

Rebuild labserver2 on new hardware as a clean, hardened secondary network sensor that reports to the primary Wazuh manager (labserver at 192.168.0.199).

---

## Work Completed

### 1. Base Operating System
- Installed Ubuntu Server 24.04.5 LTS
- Fully updated the system (`apt update && apt full-upgrade`)
- Set hostname to `labserver2`
- Confirmed SSH access

### 2. Core Hardening
- Configured UFW firewall (OpenSSH allowed)
- Enabled unattended-upgrades
- Installed and enabled Fail2ban
- Hardened SSH (`PermitRootLogin no`, `PasswordAuthentication no`)
- Enabled `auditd`

### 3. Detection Stack
- Installed Suricata
- Configured capture interface as `enp2s0`
- Updated Emerging Threats rules (`suricata-update`)
- Installed Wazuh agent 4.14.9 pointed at manager `192.168.0.199`
- Enabled and verified both services

### 4. Supporting Tools
- Installed Docker (user `kevin` added to `docker` group)
- Installed Lynis and ran initial audit
- Installed Rootkit Hunter (`rkhunter`) and performed baseline scan
- Installed lightweight utilities (`htop`, `iotop`, `ncdu`)

### 5. Operational Improvements
- Configured systemd-logind to ignore lid closure (headless operation)
- Added weekly maintenance cron:
  - Full system update + autoremove + autoclean
  - Suricata rule update and service restart
- Enabled Wi-Fi (`wlp1s0`) via Netplan for secondary management access
  - Connected to SSID `XXX_XXXXXXX`
  - Received address `192.168.1.175`

### 6. Verification
- Confirmed all key services active: Suricata, Wazuh agent, Fail2ban, auditd
- UFW active
- Suricata bound to correct interface (`enp2s0`)
- rkhunter warnings reviewed and determined to be benign
- Dual-homed management paths working (Ethernet + Wi-Fi)

---

## Final State

| Item | Value |
|------|-------|
| Hostname | labserver2 |
| Hardware | Lenovo 80TJ (AMD A6-7310) |
| RAM | ~6.7 GiB (~5.5 GiB available under normal load) |
| Ethernet | `enp2s0` – 192.168.0.110 |
| Wi-Fi | `wlp1s0` – 192.168.1.175 |
| Suricata | Active on `enp2s0` |
| Wazuh agent | Active (manager 192.168.0.199) |
| Firewall | UFW active |
| Additional | Fail2ban, auditd, Docker, Lynis, rkhunter |

---

## Key Commands Reference

```bash
# Lid close ignore
sudo nano /etc/systemd/logind.conf
# HandleLidSwitch=ignore
# HandleLidSwitchExternalPower=ignore
# HandleLidSwitchDocked=ignore
sudo systemctl restart systemd-logind

# Weekly cron
sudo crontab -e
# 0 3 * * 0 apt update && apt full-upgrade -y && apt autoremove -y && apt autoclean
# 30 3 * * 0 /usr/bin/suricata-update && /usr/bin/systemctl restart suricata

# Wi-Fi (Netplan)
sudo nano /etc/netplan/01-wifi.yaml
sudo chmod 600 /etc/netplan/01-wifi.yaml
sudo rfkill unblock all
sudo netplan apply
```

---

## Lessons Learned

- RF-kill frequently blocks laptop Wi-Fi until explicitly unblocked.
- Netplan Wi-Fi files must be mode `600` or the configuration is rejected.
- Rebuilding a sensor on different hardware is straightforward when the interface name is verified early (`enp2s0` vs previous `eno1`).
- Keeping the secondary sensor lightweight preserves resources and simplifies troubleshooting.

---

## Next Possible Steps

- Generate controlled test traffic and confirm alerts reach the Wazuh manager
- Optionally raise the Lynis hardening index with additional SSH or sysctl tweaks
- Document the dual-homed management paths in the main lab inventory

---

*Portfolio documentation for the labserver2 rebuild completed 2026-11-24.*
