# Network Traffic Analysis Report
## Generated on: 2025-11-20

### Summary
This report documents the network traffic analysis conducted on an isolated lab environment consisting of a Kali Linux workstation (attacker/analyst) and a hardened Ubuntu server (target). The objective was to simulate and analyze network traffic, identify secure and insecure protocols, and detect anomalies, aligning with SOC and Cybersecurity Analyst responsibilities.

### Traffic Analysis
1. **Baseline Traffic Capture**  
   - **Method**: Used Wireshark to capture ICMP packets from a ping test between Kali and Ubuntu.
   - **Findings**: Approximately 20 ICMP echo requests and replies observed. No packet loss detected, with an average latency of 1ms.
   - **Protocol**: ICMP (Internet Control Message Protocol).

2. **Secure Protocol Inspection (SSH)**  
   - **Method**: Captured SSH traffic on port 22 during a remote login from Kali to Ubuntu.
   - **Findings**: All packets showed encrypted payloads, confirming secure communication. No unencrypted data was exposed.
   - **Protocol**: TCP with SSH encryption.

3. **Insecure Protocol Simulation (Telnet)**  
   - **Method**: Installed and tested Telnet on Ubuntu, capturing traffic on port 23 with Wireshark.
   - **Findings**: Plaintext credentials and commands (e.g., `whoami`) were visible, highlighting significant security risks.
   - **Protocol**: TCP (unencrypted).

4. **Anomaly Detection**  
   - **Method**: Simulated a ping flood from Kali to Ubuntu and analyzed with Wireshark.
   - **Findings**: A spike in ICMP packets (over 1000 in 30 seconds) with 5% packet loss, indicating potential denial-of-service impact.
   - **Protocol**: ICMP.

### Anomalies
- **Ping Flood**: Excessive ICMP traffic suggests a possible network attack, impacting server responsiveness.
- **Telnet Exposure**: Unencrypted Telnet traffic exposed sensitive data, violating standards like PCI DSS Requirement 4.

### Recommendations
- **Rate Limiting**: Implement ICMP rate limiting on Ubuntu using UFW: `sudo ufw limit proto icmp`.
- **Disable Telnet**: Remove Telnet from the Ubuntu server: `sudo apt purge telnetd` and ensure SSH is the only remote access method.
- **Monitoring**: Enhance baseline monitoring with periodic Wireshark captures to detect deviations.

### References
- NIST SP 800-53 (AC-17: Remote Access) for secure protocol guidelines.
- Page 12 of "Cybersecurity-best-practices-guide-2024-V2.pdf" for social engineering awareness in traffic analysis.
- Page 7 of "infosec-best-practices.pdf" for incident notification best practices.

### Analyst Notes
This exercise reinforced incident triage skills from my Google Cybersecurity Professional Certificate and threat detection principles from ISC² CC. The lab setup allowed safe simulation without external impact, adhering to CFAA and ethical guidelines.