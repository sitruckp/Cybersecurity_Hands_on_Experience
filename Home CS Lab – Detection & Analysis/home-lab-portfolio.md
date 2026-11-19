# Home Cybersecurity Lab – Low-Budget Detection & Analysis Platform

**Project type:** Self-hosted cybersecurity home lab  
**Focus:** Blue-team detection, log analysis, intentionally vulnerable targets, honeypots, and lightweight AI-assisted triage  
**Status:** Active (Ubuntu Server 24.04 LTS)  
**Hardware:** Refurbished Lenovo ThinkPad E520

## Overview
Built a practical, low-cost cybersecurity lab on aging laptop hardware to gain hands-on experience with open-source detection tools, network monitoring, containerized vulnerable applications, and honeypots. The environment prioritizes stability, documentation, isolation, and reproducibility while running on limited resources (12 GB RAM).

## Hardware & Base System
- **Laptop:** Lenovo ThinkPad E520
- **CPU:** Intel Core i5-2410M (2 cores / 4 threads)
- **RAM:** 12 GB
- **Storage:** 500 GB
- **OS:** Ubuntu Server 24.04.5 LTS (headless, lid-closed)
- **Hostname:** labserver
- **Primary interface:** Ethernet (enp2s0) – 192.XXX.X.XXX
- **Access:** SSH enabled; Wi-Fi secondary

## Lab Goals
- Gain practical experience with open-source cybersecurity tools
- Focus on detection / blue-team work and log analysis
- Deploy and practice against intentionally vulnerable web applications in a controlled environment
- Explore honeypots for adversary simulation and detection practice
- Explore lightweight AI-assisted triage on constrained hardware
- Keep the host OS clean by preferring Docker where practical
- Document everything for portfolio use

## Key Work Completed
- Installed and configured Ubuntu Server 24.04 LTS in headless mode
- Set up reliable Ethernet networking after network rewiring
- Deployed and configured **Suricata** IDS on the host (user `suricata`)
  - Interface `enp2s0` placed in promiscuous mode for network visibility
- Deployed **Wazuh** single-node (manager, indexer, dashboard) via Docker
- Established Docker as the preferred method for additional services to keep the host clean and experiments reversible
- Configured UFW to restrict lab service ports to local networks only (192.168.0.0/24 and 192.168.1.0/24)

### Containerized Targets & Practice Environments (Docker)
The following intentionally vulnerable applications and related tools were deployed via Docker for safe, isolated practice:

| Service                  | Port | Purpose                                      | Notes |
|--------------------------|------|----------------------------------------------|-------|
| OWASP Juice Shop         | 3000 | Modern web vulnerabilities (OWASP Top 10+)  | Persistent container |
| DVWA                     | 8080 | Classic OWASP Top 10 practice               | Persistent container |
| Vulhub (PHP CVE-2019-11043) | 8082 | Real-world PHP-FPM RCE example             | Started, tested from Kali, then cleanly removed with `docker compose down -v` |
| Cowrie SSH Honeypot      | 2222 | SSH honeypot for adversary simulation       | Running with Docker named volume for persistent logs |

- **Cowrie troubleshooting & resolution:** Initial host-bind mount had permission issues (UID mismatch). Resolved by switching to a Docker named volume (`cowrie-data`). Successfully accepted SSH connections, logged full sessions (login + commands), and confirmed JSON logging.
- All vulnerable targets and the honeypot are restricted by UFW to the local network only. No public exposure.
- Demonstrated clean start/stop workflow for Vulhub environments to conserve resources on 12 GB RAM.

## Skills & Concepts Demonstrated
- Linux server administration (Ubuntu Server, SSH, networking, headless operation, UFW firewall)
- Network intrusion detection system (NIDS) deployment with Suricata
- SIEM / endpoint detection with Wazuh (single-node Docker deployment)
- Docker containerization for isolation, reproducibility, and clean host management
- Deployment of intentionally vulnerable applications (Juice Shop, DVWA, Vulhub) for web security practice
- Honeypot deployment (Cowrie) including volume/permission troubleshooting and log verification
- Resource-aware architecture on constrained hardware (12 GB RAM)
- Lab safety practices (network isolation, local-only exposure, clean teardown of temporary environments)
- Documentation and portfolio-oriented project management

## Design Decisions
- Stayed on Ubuntu 24.04 LTS (supported until 2029) rather than immediately upgrading to 26.04 for stability of the detection stack
- Kept Suricata on the host for reliable packet capture while using Docker for most other tools and targets
- Isolated vulnerable applications and honeypots in Docker to reduce risk and simplify teardown
- Used Docker named volumes where host UID mismatches occurred (Cowrie)
- Prioritized observability and clean configuration over adding unnecessary services
- Emphasized lab safety: services not exposed to the public internet

## Future Direction
- Complete Wazuh integration and agent connectivity
- Forward Cowrie and Suricata logs into Wazuh for centralized analysis
- Add log analysis and alerting workflows (including correlation between Suricata events and honeypot/vulnerable app activity)
- Introduce lightweight AI-assisted triage of Suricata/Wazuh events
- Expand detection rules and practice response playbooks
- Continue documenting configurations, findings, and lessons learned

## Tech Stack
- Ubuntu Server 24.04 LTS
- Suricata (host-based IDS)
- Wazuh (single-node Docker)
- Docker / Docker Compose
- OWASP Juice Shop
- DVWA
- Vulhub (CVE environments)
- Cowrie (SSH honeypot)
- UFW
- SSH, standard Linux networking tools

## Notes
This lab is for educational and defensive skill-building purposes only. All vulnerable applications and honeypots are run in an isolated environment restricted to the local network.
