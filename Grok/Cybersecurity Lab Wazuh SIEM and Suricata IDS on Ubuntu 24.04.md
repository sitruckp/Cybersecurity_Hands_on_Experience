Cybersecurity Lab: Wazuh SIEM and Suricata IDS on Ubuntu 24.04
Date: November 25, 2025
Author: Kevin
Purpose: Documenting the installation, configuration, troubleshooting, and testing of Wazuh (SIEM/XDR for host monitoring) and Suricata (IDS for network monitoring) on my Ubuntu laptop for cybersecurity labs, aligned with Google Cybersecurity course, IBM Cybersecurity Analyst, and CompTIA Security+ preparation.
Overview
As part of my transition from educational technology and bio-defense to cybersecurity, I set up Wazuh 4.14.1 and Suricata 8.0.2 on my Ubuntu 24.04 laptop (HP, IPs: 192.168.1.XXX on wlo1, 192.168.1.XXX on eno1). This lab builds on my Linux skills (Kali, Ubuntu, Debian), hands-on experience with Wireshark, Lynis, Metasploit, and certifications (ISC2 CC, Google Cybersecurity Professional). The goal was to monitor host logs and network traffic, detect Kali Linux nmap scans, and troubleshoot issues like dependency conflicts, rule errors, and kernel quirks. Wazuh proved challenging, leading to a pivot to Suricata, which was more successful for network monitoring.

Prerequisites
System: Ubuntu 24.04 (Noble), kernel 6.x (uname -r)
Interfaces: wlo1 (Wi-Fi, 192.168.1.XXX/24), eno1 (Ethernet, 192.168.1.XXX/24)
Tools: Kali Linux laptop for generating test scans
Skills: Linux commands, Wireshark, Metasploit, Lynis, basic networking
Resources: Wazuh Docs, Suricata Docs, Emerging Threats Rules, TryHackMe, Cybernews

Wazuh SIEM Setup
Wazuh is an open-source SIEM/XDR for host-based monitoring (logs, file integrity, vulnerabilities). I attempted an all-in-one setup (manager, indexer, dashboard) but hit repeated snags, leading to a pivot to Suricata.

Installation Attempts
Initial Manual Install:
Added Wazuh repository and key: curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg and echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list and sudo apt update

Installed components: sudo apt install wazuh-indexer wazuh-manager wazuh-dashboard
Issue: wazuh-indexer failed to start: Job for wazuh-indexer.service failed because the control process exited with error code.

Quickstart Script:
Ran official script: curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
Success: Installed all components, started services, and accessed dashboard at https://localhost with admin credentials from wazuh-install-files.tar.
Output Example: 25/11/2025 09:53:59 INFO: You can access the web interface https://<wazuh-dashboard-ip>:443 User: admin Password: <generated>

Agent Setup:
Installed agent: sudo apt install wazuh-agent
Issue: Conflict with wazuh-manager: mv: cannot overwrite '/var/ossec/etc/shared/default': Directory not empty dpkg: error processing package wazuh-agent (--configure)
Attempted registration: sudo /var/ossec/bin/manage_agents -i 127.0.0.1
Failed: Invalid authentication key.

Reinstall Attempts:
Purged components: sudo apt purge wazuh-agent wazuh-indexer wazuh-dashboard filebeat -y and sudo rm -rf /etc/filebeat /var/lib/filebeat /var/log/filebeat /var/ossec /etc/wazuh-indexer /etc/wazuh-dashboard /var/lib/wazuh-indexer /usr/share/wazuh-dashboard
Reran quickstart with overwrite: curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a -o
Issue: Filebeat conflict: ERROR: Filebeat already installed.
Final Issue: Manager missing: Unit wazuh-manager.service could not be found.


Troubleshooting
Permission Denied on GPG Key:
Fixed: curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

Filebeat Conflict: Removed Filebeat and configs: sudo apt purge filebeat -y and sudo rm -rf /etc/filebeat /var/lib/filebeat /var/log/filebeat
Agent Key Error: Attempted re-registration, but manager absence blocked progress.
Outcome: Wazuh’s complexity (dependency conflicts, resource demands) led to pivoting to Suricata for simpler network monitoring.

Lessons Learned
Wazuh’s all-in-one setup may be better for VMs or servers, not laptops at least in this case.
Dependency management (Filebeat, manager-agent conflicts) requires thorough cleanup.
SIEM concepts (logs, agents, dashboards) are critical for Security+ but need stable setups.

Suricata IDS Setup
Suricata is an open-source IDS for network traffic analysis, ideal for detecting intrusions like nmap scans. I successfully installed and configured it to monitor wlo1 and eno1.

Installation
Add PPA and Install:
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
Verified: suricata --build-info (version 8.0.2).

Update Rules:
sudo suricata-update
Output: Loaded 62330 rules, enabled 46515 from Emerging Threats Open

Configuration
Edit suricata.yaml:
sudo nano /etc/suricata/suricata.yaml
Set HOME_NET:
vars:
address-groups:
HOME_NET: "[192.168.1.X/24]"
EXTERNAL_NET: "!$HOME_NET"
HTTP_SERVERS: "$HOME_NET"
SMTP_SERVERS: "$HOME_NET"
SQL_SERVERS: "$HOME_NET"
DNS_SERVERS: "$HOME_NET"
TELNET_SERVERS: "$HOME_NET"
Configured af-packet for both interfaces:
af-packet:
interface: wlo1
threads: auto
cluster-id: 95
cluster-type: cluster_cpu
defrag: yes
use-mmap: yes
ring-size: 65536
interface: eno1
threads: auto
cluster-id: 94
cluster-type: cluster_cpu
defrag: yes
use-mmap: yes
ring-size: 65536

Start Service:
sudo systemctl enable suricata && sudo systemctl start suricata
sudo systemctl status suricata
Output: Active (running), 222 MB memory

Troubleshooting
Missing Rules:
Issue: sudo suricata -T warned: W: detect: No rule files match the pattern /var/lib/suricata/rules/suricata.rules
Fix: Ran sudo suricata-update.
Verification: ls -l /var/lib/suricata/rules/ Confirmed suricata.rules exists

Custom Rules Error:
Issue: Added suppress gen_id 1, sig_id 2200121 to /var/lib/suricata/rules/custom.rules: echo "suppress gen_id 1, sig_id 2200121" | sudo tee /var/lib/suricata/rules/custom.rules
Got error: E: detect-parse: no rule options. E: detect: error parsing signature "suppress gen_id 1, sig_id 2200121"
Attempts: echo "suppress gen_id 1, sig_id 2200121, track by_src, ip 0.0.0.0/0" | sudo tee /var/lib/suricata/rules/custom.rules and echo "threshold gen_id 1, sig_id 2200121, type threshold, track by_src, count 0, seconds 3600" | sudo tee /var/lib/suricata/rules/custom.rules
Both failed with similar errors.
Temporary Fix: Removed custom.rules: sudo mv /var/lib/suricata/rules/custom.rules /var/lib/suricata/rules/custom.rules.bak and sudo nano /etc/suricata/suricata.yaml Removed - custom.rules from rule-files
Status: Unresolved; needs correct suppress syntax.

Fanout Error:
Issue: Live tests (sudo suricata -c /etc/suricata/suricata.yaml -i wlo1/eno1) gave: E: af-packet: fanout not supported by kernel: Kernel too old or cluster-id 99 already in use.
Fix: Used cluster_cpu and unique cluster-ids (95, 94): sudo systemctl stop suricata and sudo nano /etc/suricata/suricata.yaml Set cluster-type: cluster_cpu, cluster-id: 95 (wlo1), 94 (eno1)
Verification: sudo suricata -c /etc/suricata/suricata.yaml -i wlo1 Repeated for eno1
Status: Error persisted; likely kernel or process conflict.

Permission Issue:
Issue: cat /var/lib/suricata/rules/custom.rules gave Permission denied
Fix: sudo chmod 644 /var/lib/suricata/rules/custom.rules and sudo ls -l /var/lib/suricata/rules/custom.rules -rw-r--r-- 1 root suricata

Testing
Generate Traffic:
From Kali: nmap -sS -p 1-1000 192.168.1.XXX and nmap -sS -p 1-1000 192.168.1.XXX
Local: nmap -sS -p 1-1000 8.8.8.8 -e wlo1 and curl http://testmyids.com

Check Alerts:
sudo cat /var/log/suricata/fast.log
Detections:
ET INFO Possible Kali Linux hostname in DHCP Request Packet (sid:2022973, Priority 1):
Flagged Kali’s DHCP broadcasts, showing IDS detection of pentesting tools.
Example: 11/25/2025-11:18:50.061775 [] [1:2022973:1] ET INFO Possible Kali Linux hostname in DHCP Request Packet [] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {UDP} 0.0.0.0:68 -> 255.255.255.255:67

SURICATA Ethertype unknown (sid:2200121, Priority 3):
Noisy alerts from LLDP/ARP broadcasts. Suppression attempts failed.

Nmap Scans: No clear ET SCAN NMAP alerts, possibly due to local scans bypassing interfaces (wlo1/eno1) or rule tuning needs.

Verify Traffic:
sudo tcpdump -i wlo1 -c 10
sudo tcpdump -i eno1 -c 10
Confirmed packets on both interfaces.

Lessons Learned
Wazuh Challenges: SIEM setups are complex and resource-heavy, better suited for VMs. Learned agent registration, dashboard navigation, and dependency management.
Suricata Success: IDS is lighter and ideal for network labs. Mastered multi-interface monitoring (wlo1, eno1) and rule updates.
Troubleshooting: Debugged permissions, kernel errors (fanout), and rule syntax, mirroring Wireshark and Metasploit lab skills.
Lab Value: Detecting Kali’s DHCP footprint is resume-worthy, showing real-world threat detection for Security+ and career prep.
GitHub Documentation: Creating a polished .md file enhances my portfolio, showcasing Linux and cybersecurity expertise.

Next Steps
Wazuh: Retry on a VM to avoid laptop conflicts, focusing on agent monitoring for host logs.
Suricata:
Resolve custom.rules error with correct suppress syntax for sid:2200121.
Fix fanout error by checking kernel (uname -r) and processes (ps aux | grep suricata).
Tune rules for nmap detection: grep "ET SCAN" /var/lib/suricata/rules/suricata.rules
Test additional traffic: hping3 -S 192.168.1.XXX -p 80 -c 1000 and curl http://testmyids.com

Expand Lab: Install Suricata on Kali for dual IDS setup and document in repo.
GitHub: Add screenshots of fast.log or systemctl status suricata to enhance lab_setup.md. sudo cat /var/log/suricata/fast.log | grep "ET INFO" > kali_alerts.txt
Study: Create flashcards on SIEM vs. IDS, rule syntax, and alert analysis for Security+ prep.

Commands Reference
Wazuh:
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
sudo apt install wazuh-agent
sudo /var/ossec/bin/manage_agents -i 127.0.0.1
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt

Suricata:
sudo apt install suricata -y
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo suricata -c /etc/suricata/suricata.yaml -i wlo1
sudo cat /var/log/suricata/fast.log
sudo systemctl status suricata

Resources
Wazuh Documentation
Suricata Documentation
Emerging Threats Rules
TryHackMe IDS Labs
Cybernews Threat Updates

This lab reflects my cybersecurity journey, blending Linux skills and hands-on tools for analyst roles. Feedback welcome on my GitHub repo!