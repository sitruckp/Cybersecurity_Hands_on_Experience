# Labserver2 Build & Hardening Log

**Date:** 2026-11-23  
**Machine:** HP Laptop 17-by1xxx (labserver2)  
**Role:** Secondary Suricata sensor  
**Operator:** kevin  

---

## Hardware & OS

| Item | Value |
|------|-------|
| Model | HP Laptop 17-by1xxx |
| CPU | Intel Core i5-8265U (4 cores / 8 threads) |
| RAM | 7.6 GiB |
| Disk | 238.5 GB NVMe (100 GB LVM root) |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-151-generic |
| Hostname | labserver2 |
| Primary IP | 192.168.0.101 (`eno1`) |

---

## Goals for This Session

- Establish a clean baseline
- Remove unnecessary heavy services (MicroK8s and related snaps)
- Get Suricata running as a network sensor
- Apply basic host hardening
- Document the final state for portfolio use

---

## Work Performed

### 1. Baseline Collection
- Captured system identity, hardware, network, listening ports, and running processes
- Identified MicroK8s + Calico networking and multiple heavy snaps (Nextcloud, Rocket.Chat, Wekan, Prometheus, SABnzbd, etc.)
- Noted Suricata was installed but failed to start
- Observed high initial process count and temporary zombie processes

### 2. Cleanup
- Removed MicroK8s
- Removed heavy snaps: nextcloud, rocketchat-server, wekan, prometheus, sabnzbd, mosquitto
- Ran `apt autoremove`
- Result: Memory usage dropped from ~2.6 GiB to under 1 GiB; Calico interfaces disappeared

### 3. Suricata Configuration
- Diagnosed failure: Suricata was configured for `eth0` (interface does not exist)
- Changed capture interface to `eno1` in `/etc/suricata/suricata.yaml`
- Validated configuration with `suricata -T`
- Started and enabled the service
- Ran `suricata-update` (Emerging Threats Open rules)
- Loaded approximately 53,530 enabled rules
- Confirmed service remains active after restart
- Added weekly rule-update cron job

### 4. Basic Hardening
- Enabled UFW firewall (OpenSSH allowed)
- Added user `kevin` to the `docker` group
- Confirmed SSH settings: `PermitRootLogin no`, `PasswordAuthentication no`
- Enabled unattended-upgrades
- Installed and enabled Fail2ban
- Installed lightweight utilities: htop, iotop, ncdu

### 5. Detection & Audit Tools
- Installed Wazuh agent (pointed at primary manager 192.168.0.199)
- Installed Lynis and ran full system audit
- Installed Rootkit Hunter (`rkhunter`) and performed an initial check
- Enabled `auditd`

### 6. Wi-Fi Attempt (Deferred)
- Identified onboard Realtek RTL8723DE
- Driver loaded but failed with “mac power on failed”
- Decision: Skip Wi-Fi for now (not required for the sensor role)

---

## Final State

| Component | Status |
|-----------|--------|
| Suricata | Active (running) on `eno1` with full rule set |
| Wazuh agent | Installed and enabled |
| UFW | Active (SSH allowed) |
| Fail2ban | Active |
| Lynis hardening index | 58 / 100 |
| Malware scanner | rkhunter installed |
| Docker | Installed; user has group access |
| MicroK8s / heavy snaps | Removed |
| Available RAM | ~6.2 GiB free under normal load |

### Expected / Acceptable Warnings
- Promiscuous mode on `eno1` (required for Suricata)
- Minor package updates available
- Various optional Lynis suggestions (SSH tweaks, banners, sysctl, etc.)

---

## Key Commands Used (Reference)

```bash
# Cleanup
sudo snap remove microk8s nextcloud rocketchat-server wekan prometheus sabnzbd mosquitto
sudo apt autoremove -y

# Suricata
sudo nano /etc/suricata/suricata.yaml   # change eth0 → eno1
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo suricata-update

# Hardening
sudo ufw allow OpenSSH && sudo ufw enable
sudo usermod -aG docker kevin
sudo apt install -y fail2ban unattended-upgrades
sudo systemctl enable --now fail2ban

# Audit tools
sudo apt install -y lynis rkhunter auditd
sudo lynis audit system
sudo rkhunter --update && sudo rkhunter --check --sk
```

---

## Lessons & Notes

- Always verify the actual interface name before configuring an IDS (`ip a` / `ip link`).
- MicroK8s and desktop-oriented snaps are resource-heavy on a 7.6 GB sensor host.
- A secondary sensor benefits from shipping alerts to a central manager (Wazuh) rather than running its own full stack.
- Promiscuous mode warnings from auditing tools are expected on an IDS sensor.
- Hardware Wi-Fi issues (RTL8723DE power failure) can be safely deferred when Ethernet is available.

---

## Next Possible Steps

- Whitelist the `eno1` promiscuous interface in Lynis if desired
- Add a few additional SSH hardening options
- Begin build of the Lenovo 80TJ as the vulnerable target
- Document traffic-generation tests against this sensor

---

*Document created for portfolio and operational reference. Machine role: secondary network sensor.*
