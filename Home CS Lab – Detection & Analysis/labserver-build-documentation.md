# Lab Server Build Documentation

**Server:** labserver  
**Hardware:** Lenovo ThinkPad E520  
**OS:** Ubuntu Server 24.04.5 LTS  
**User:** kevin  
**Primary interface:** enp2s0 (Ethernet) — 192.168.0.199  
**Wi-Fi interface:** (still present) — 192.168.1.184 / labserver.lan  
**Purpose:** Low-resource open-source cybersecurity home lab (detection, log analysis, blue-team tools, lightweight AI experiments)

Last updated: 2026-11-23

---

## Hardware Summary

- **Model:** Lenovo ThinkPad E520
- **CPU:** Intel Core i5-2410M (2 cores / 4 threads)
- **RAM:** 12 GB
- **Disk:** 500 GB
- **Notes:** Running headless with lid closed. Ethernet is the primary management interface after network rewiring (2026-11-11).

---

## 1. Base Operating System

**What:** Ubuntu Server 24.04.5 LTS (minimal install)  
**Why:** Stable, long-term support, good package availability, and light enough for 12 GB RAM.  
**Cybersecurity tie-in:** Clean, supported base reduces attack surface before adding detection tools.

Typical installation choices used:
- Minimal server install (no GUI)
- OpenSSH server selected during install
- Hostname set to `labserver`
- Primary user created as `kevin`

Post-install first steps (run as root or with sudo):

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y curl git vim htop net-tools
```

Success looks like: system is fully updated and basic troubleshooting tools are present.

---

## 2. Hostname & Basic Identity

```bash
sudo hostnamectl set-hostname labserver
# Verify
hostnamectl
```

---

## 3. SSH Access

SSH was enabled during OS install. Additional hardening/common steps:

```bash
sudo systemctl enable --now ssh
sudo systemctl status ssh
```

Optional (recommended) — disable password auth after key is working:

```bash
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no
# Set: PermitRootLogin no
sudo systemctl restart ssh
```

---

## 4. Headless / Lid-Closed Operation

Configured so the laptop continues running with the lid closed.

```bash
sudo nano /etc/systemd/logind.conf
```

Typical lines set:

```
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
```

Then:

```bash
sudo systemctl restart systemd-logind
```

Success: closing the lid no longer suspends or powers off the machine.

---

## 5. Network Configuration

**Current state (as of 2026-11-11 rewiring):**
- Ethernet (`enp2s0`): 192.168.0.199
- Wi-Fi still shows as 192.168.1.184 (labserver.lan)

Netplan is the standard method on Ubuntu Server 24.04.

Example `/etc/netplan/00-installer-config.yaml` style configuration (adjust as needed):

```yaml
network:
  version: 2
  ethernets:
    enp2s0:
      dhcp4: true
      # or static if preferred
  wifis:
    # Wi-Fi interface name
      dhcp4: true
```

Apply:

```bash
sudo netplan apply
ip addr show
```

After the network change on 2026-11-11, any agents (especially Wazuh) needed their manager address updated to `192.168.0.199`.

---

## 6. Suricata IDS

**What:** Suricata network intrusion detection system  
**Why:** Packet-level visibility and signature-based detection on the lab network.  
**Cybersecurity tie-in:** Core blue-team sensor for detecting scanning, malware C2, and anomalous traffic.  
**Resource note:** Moderate CPU/RAM usage; runs well on this hardware when rules are managed carefully.

Running as user `suricata`, with `enp2s0` in promiscuous mode.

Typical install and basic setup:

```bash
sudo apt update
sudo apt install -y suricata
sudo systemctl enable --now suricata
```

Common configuration touches:
- Edit `/etc/suricata/suricata.yaml` to set the correct interface (`enp2s0`)
- Enable promiscuous mode (usually default or set via capture settings)
- Update rules periodically

Basic status check:

```bash
sudo systemctl status suricata
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Success: Suricata is active and listening on `enp2s0`.

---

## 7. Wazuh Manager

**What:** Wazuh security monitoring platform (manager component)  
**Why:** Centralized log analysis, file integrity monitoring, vulnerability detection, and agent management.  
**Cybersecurity tie-in:** Production-style SIEM/XDR capability for the lab; excellent for portfolio documentation.  
**Resource note:** Manager is heavier than a pure sensor. Monitor RAM carefully on 12 GB systems; avoid running too many agents locally if memory becomes tight.

Current known state: Manager is running on labserver. Agents must point to `192.168.0.199` after the 2026-11-11 network change.

Typical Docker-based or native install path used in this lab style (Docker preferred for cleanliness):

```bash
# Example Docker approach (adjust tags/volumes as used)
docker run -d --name wazuh-manager \
  --restart unless-stopped \
  -p 1514:1514/udp \
  -p 1515:1515/tcp \
  -p 55000:55000/tcp \
  -v wazuh-manager-data:/var/ossec/data \
  wazuh/wazuh-manager:latest
```

Or native package install if that was chosen.

Status check:

```bash
docker ps | grep wazuh
# or
sudo systemctl status wazuh-manager
```

---

## 8. Docker (Recommended / Preferred)

Docker is the preferred way to run most lab services so the host stays clean and experiments are easy to remove.

Typical install:

```bash
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker kevin
# Log out and back in for group to take effect
```

Verify:

```bash
docker run --rm hello-world
docker compose version
```

---

## 9. Safety & Operational Notes

- Services are intended for isolated lab use only. Do not expose management ports (SSH, Wazuh dashboard, etc.) to the public internet.
- Ethernet (192.168.0.199) is the primary management address.
- After any network change, update agent configurations (especially Wazuh) to the new manager IP.
- Monitor resource usage (`htop`, `free -h`, `docker stats`) — 12 GB RAM is workable but not unlimited.
- Keep the host OS minimal; prefer containers for new tools.

---

## 10. Quick Status Commands (Current Lab)

```bash
hostnamectl
ip addr show
systemctl status ssh
systemctl status suricata
docker ps
free -h
```

---

## Next Recommended Actions

1. Document exact Suricata rule-update process and current rule sources.
2. Capture the exact Wazuh deployment method (native vs Docker) and agent registration steps.
3. Add a simple monitoring or logging note for resource usage over time.

---

*This document was reconstructed from the known running configuration of labserver for portfolio and operational use. Exact one-time command history may vary slightly from the standardized steps shown above.*
