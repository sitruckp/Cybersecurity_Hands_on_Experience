# Lab Server Build Documentation

**Lab:** Open-source cybersecurity home lab  
**Primary user:** kevin  
**Last updated:** 2026-11-23  

**Purpose:** Low-resource open-source cybersecurity home lab focused on detection, log analysis, blue-team tools, and lightweight AI experiments. Docker preferred where practical.

---

## Lab Inventory

| Hostname     | Hardware                  | CPU                  | RAM   | Role                          | Primary IP      | OS                     |
|--------------|---------------------------|----------------------|-------|-------------------------------|-----------------|------------------------|
| labserver    | Lenovo ThinkPad E520      | i5-2410M (2c/4t)     | 12 GB | Primary (Wazuh manager)       | 192.168.0.199   | Ubuntu Server 24.04.5  |
| labserver2   | HP Laptop 17-by1xxx       | i5-8265U (4c/8t)     | 7.6 GB| Secondary Suricata sensor     | 192.168.0.101   | Ubuntu Server 24.04.5  |
| (Lenovo 80TJ)| Lenovo 80TJ               | AMD A6-7310          | 8 GB  | Vulnerable target (planned)   | —               | Ubuntu (to be rebuilt) |
| (Celeron)    | —                         | Celeron N2920        | 3.6 GB| Son’s server                  | —               | —                      |

---

## 1. labserver (Primary – ThinkPad E520)

### Hardware Summary
- **Model:** Lenovo ThinkPad E520
- **CPU:** Intel Core i5-2410M (2 cores / 4 threads)
- **RAM:** 12 GB
- **Disk:** 500 GB
- **Notes:** Headless, lid-closed operation configured. Ethernet (`enp2s0`) is primary after 2026-11-11 network rewiring.

### Key Configuration
- Hostname: `labserver`
- User: `kevin`
- Ethernet: `enp2s0` → 192.168.0.199
- Wi-Fi still present: 192.168.1.184 (`labserver.lan`)
- SSH enabled
- Suricata running (user `suricata`, promiscuous mode on `enp2s0`)
- Wazuh manager running (agents must point to 192.168.0.199)

### Notable Setup Steps
- Ubuntu Server 24.04.5 LTS minimal install
- Headless lid-closed config in `/etc/systemd/logind.conf`
- Docker installed (preferred for services)
- Suricata installed and configured for `enp2s0`
- Wazuh manager deployed

---

## 2. labserver2 (Secondary Sensor – HP 17-by1xxx)

### Hardware Summary
- **Model:** HP Laptop 17-by1xxx
- **CPU:** Intel Core i5-8265U (4 cores / 8 threads)
- **RAM:** 7.6 GiB
- **Disk:** 238.5 GB NVMe (100 GB LVM root)
- **OS:** Ubuntu 24.04.5 LTS
- **Kernel:** 6.8.0-151-generic

### Role
Secondary Suricata network sensor. Feeds alerts to the primary Wazuh manager on labserver.

### Work Completed (2026-11-23)

#### Cleanup
- Removed MicroK8s and heavy snaps (Nextcloud, Rocket.Chat, Wekan, Prometheus, SABnzbd, Mosquitto)
- Freed significant RAM (usage dropped from ~2.6 GiB to <1 GiB)

#### Suricata
- Fixed failed service (was configured for non-existent `eth0`)
- Set interface to `eno1`
- Updated rules via `suricata-update` (~53,530 enabled rules)
- Service active and running
- Weekly rule-update cron added

#### Hardening & Tools
- UFW enabled (OpenSSH allowed)
- Fail2ban installed and enabled
- Unattended-upgrades enabled
- SSH: `PermitRootLogin no`, `PasswordAuthentication no`
- User `kevin` added to `docker` group
- Wazuh agent installed and pointed at `192.168.0.199`
- Lynis installed (hardening index 58/100)
- Rootkit Hunter (`rkhunter`) installed
- `auditd` enabled
- Lightweight tools: htop, iotop, ncdu

#### Deferred
- Onboard Wi-Fi (Realtek RTL8723DE) — driver fails with “mac power on failed”. Skipped; Ethernet is sufficient.

### Current Status
- Suricata: active on `eno1`
- Wazuh agent: enabled
- Firewall + Fail2ban: active
- Clean, low-resource sensor host

---

## 3. Common Practices

### Docker (Preferred)
Used on both servers where practical so experiments stay isolated.

### Safety Notes
- Lab use only — do not expose management ports to the internet
- After network changes, update Wazuh agent manager addresses
- Monitor RAM (`free -h`, `htop`) — especially on the 7.6 GB sensor
- Keep host OS minimal

### Quick Status Commands
```bash
hostnamectl
ip addr show
systemctl status ssh suricata wazuh-agent 2>/dev/null
sudo ufw status
free -h
```

---

## Next Recommended Actions

1. Finish documentation of exact Wazuh manager deployment method on labserver
2. Begin clean build of Lenovo 80TJ as the vulnerable target
3. Optionally apply additional SSH hardening or Lynis suggestions on labserver2
4. Test end-to-end alert flow (Suricata on labserver2 → Wazuh on labserver)

---

*Document maintained for portfolio and operational use. Updated 2026-11-23 to include labserver2.*
