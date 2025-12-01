# Week 6: Security Assessment and Testing - Lab Progress Report

## Overview
This report documents my hands-on progress in Week 6 of the 10-week cybersecurity learning plan, focused on vulnerability scanning as a key SOC Analyst skill. Using my home lab (Kali Linux on Lenovo ThinkPad as the scanning workstation and hardened Ubuntu 24.04 server on HP laptop as the target), I conducted ethical scans to identify and analyze risks. All activities were confined to my isolated lab environment, adhering to ethical guidelines from "ethical hacking, student guide.pdf" (page 2) and legal standards like CFAA.

**Date Completed:** December 01, 2025  
**Lab Setup Recap:** Ubuntu server (IP: 192.168.1.183, Lynis score: 85/100) with UFW, SSH on port 2222, key-based auth. Kali for tools like Nmap, OpenVAS, Nikto.

## Objectives
1. Conduct vulnerability scans to identify and prioritize risks on lab assets, simulating SOC triage processes.
2. Analyze scan results to recommend mitigations, aligning with incident response basics from Google Cybersecurity Professional Certificate.
3. Understand scanning tools' role in compliance audits, such as those in NIST SP 800-53's RA-5 (Vulnerability Monitoring and Scanning).

## Prerequisites
- On Kali: Installed OpenVAS (`sudo apt update && sudo apt install openvas -y; sudo gvm-setup; sudo gvm-start`) and Nikto (`sudo apt install nikto -y`).
- On Ubuntu: Enabled Apache for web scanning (`sudo apt install apache2; sudo ufw allow 80/tcp; sudo systemctl start apache2`).
- Verified network: Ping from Kali to Ubuntu IP.

## Core Exercises

### Exercise 1: Basic Network Discovery Scan (Nmap)
**Scenario:** Perform reconnaissance to map the Ubuntu server's attack surface, mimicking pre-attack intel gathering for SOC threat hunting.

**Tool Explanation:** Nmap is a network mapper tool for discovering hosts, services, and vulnerabilities on a network. It sends packets to probe ports and identify open services, helping analysts map attack surfaces and detect misconfigurations—relevant for vulnerability assessment in MITRE ATT&CK's Reconnaissance tactic.

**Steps and Commands:**
1. Basic port/OS scan:
   ```
   sudo nmap -sV -O 192.168.1.183
   ```
   **Output:**
   ```
   Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 13:28 EST
   Nmap scan report for labserver.lan (192.168.1.183)
   Host is up (0.0018s latency).
   Not shown: 998 closed tcp ports (reset)
   PORT STATE SERVICE VERSION
   25/tcp filtered smtp
   2222/tcp open ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
   MAC Address: C8:A3:62:84:0C:72 (Asix Electronics)
   Device type: general purpose|router
   Running: Linux 5.X, MikroTik RouterOS 7.X
   OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
   OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
   Network Distance: 1 hop
   Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
   OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
   Nmap done: 1 IP address (1 host up) scanned in 5.76 seconds
   ```
2. Vulnerability scripting:
   ```
   sudo nmap --script vuln 192.168.1.183
   ```
   **Output:**
   ```
   Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 13:54 EST
   Pre-scan script results:
   | broadcast-avahi-dos: 
   |   Discovered hosts:
   |     224.0.0.251
   |   After NULL UDP avahi packet DoS (CVE-2011-1002).
   |_  Hosts are all up (not vulnerable).
   Nmap scan report for labserver.lan (192.168.1.183)
   Host is up (0.0014s latency).
   Not shown: 998 closed tcp ports (reset)
   PORT     STATE    SERVICE
   25/tcp   filtered smtp
   2222/tcp open     EtherNetIP-1
   MAC Address: C8:A3:62:84:0C:72 (Asix Electronics)

   Nmap done: 1 IP address (1 host up) scanned in 36.43 seconds
   ```

**Debrief:** Logged results in `scan_results.txt`. Key findings: Open SSH on non-standard port (good evasion), filtered SMTP. No major vulns flagged, but cross-checked for CVE-2024-6387 (patched in this version). Pitfall: OS guess inaccuracy—verified manually with `uname -r` on Ubuntu. Builds on ISC² CC's vulnerability management: Prioritized SSH as potential entry point.

### Exercise 2: Full Vulnerability Scan with OpenVAS
**Scenario:** Simulate a quarterly vuln assessment on the Ubuntu server to identify exploitable weaknesses.

**Tool Explanation:** OpenVAS (via GVM) is an open-source vulnerability scanner that checks for known CVEs by probing systems with safe exploits and signatures. It automates detection of outdated software or misconfigs, essential for SOC roles in ongoing threat hunting per CIS Controls' Continuous Vulnerability Management.

**Steps and Commands:**
- Setup: `sudo gvm-setup; sudo gvm-start; sudo gvm-check-setup` (outputs confirmed services OK, feeds updated).
- UI: Created target "Labserver" (IP: 192.168.1.183), task "Scan Labserver" with "Full and fast" config.
- Results (from XML exports): Low severity issues like weak SSH MAC algorithms (CVSS 2.6) and ICMP timestamp disclosure (CVSS 2.1). CPE: Ubuntu 24.04, OpenSSH 9.6p1.

**Key Output Snippet (from results-20251201.xml):**
- Weak MAC: umac-64-etm@openssh.com (client-to-server/server-to-client).
- ICMP Disclosure: Enables fingerprinting.
- Total: 13 results (2 low, 11 log).

**Debrief:** Exported report (attempted PDF). Analyzed: Triaged lows; no highs due to hardening. Pitfall: False positives—verified SSH version patched. Ties to Google cert's threat detection: Logged in simulated ticket.

### Exercise 3: Targeted Web Application Scan (Nikto)
**Scenario:** Test for web vulns on Apache server running on Ubuntu.

**Tool Explanation:** Nikto is a web server scanner that tests for outdated versions, dangerous files, and common misconfigs like directory listing. It complements OpenVAS by focusing on HTTP/HTTPS, aiding in web app security testing per OWASP's Top 10 risks.

**Steps and Commands:**
1. HTTP scan:
   ```
   nikto -h http://192.168.1.183
   ```
   **Output:**
   ```
   - Nikto v2.5.0
   ---------------------------------------------------------------------------
   + Target IP:          192.168.1.183
   + Target Hostname:    192.168.1.183
   + Target Port:        80
   + Start Time:         2025-12-01 14:41:05 (GMT-5)
   ---------------------------------------------------------------------------
   + Server: Apache/2.4.58 (Ubuntu)
   + /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
   + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
   + No CGI Directories found (use '-C all' to force check all possible dirs)
   + /: Server may leak inodes via ETags, header found with file /, inode: 29af, size: 644e923c5f9e3, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
   + OPTIONS: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD .
   + 8102 requests: 0 error(s) and 4 item(s) reported on remote host
   + End Time:           2025-12-01 14:41:43 (GMT-5) (38 seconds)
   ---------------------------------------------------------------------------
   + 1 host(s) tested
   ```
2. HTTPS scan (no results as not enabled):
   ```
   nikto -h https://192.168.1.183 -ssl
   ```

**Debrief:** Findings: Missing security headers (clickjacking/MIME risks), minor ETag leak (low impact). Pitfall: Nikto DB outdated for Apache 2.4.58. Builds on ISC² CC's app security: Identified OWASP A05 misconfigs.

## Assessment: Mini-Report
- **Scan Summary:** Tools: Nmap, OpenVAS, Nikto. Target: 192.168.1.183. Duration: ~1 hour total.
- **Key Findings:** 
  - Nmap: Open SSH (potential CVE-2024-6387, but patched); filtered ports.
  - OpenVAS: Weak SSH MACs (CVSS 2.6), ICMP disclosure (CVSS 2.1).
  - Nikto: Missing headers, ETag leak (CVE-2003-1418, low risk).
- **Recommendations:** Implement stronger MACs, block ICMP, add web headers (see prompt for details).
- **Lessons Learned:** Scanning simulates SOC vuln triage; reduced attack surface via prior hardening.

**Self-Check Quiz:**
1. What Nmap flag detects service versions? (-sV)
2. Why prioritize high-severity OpenVAS results? (Risk-based response per NIST)
3. Name an OWASP risk Nikto detected. (A05: Misconfiguration)
4. How does this build on Week 5's IAM? (Scans tested SSH auth)
5. True/False: Scanning replaces patching. (False)

## Resources
- TryHackMe "OpenVAS" and "Nikto" rooms: https://tryhackme.com/room/openvas, https://tryhackme.com/room/niktobasics
- SANS Vuln Management: https://www.sans.org/reading-room/whitepapers/testing/paper/386
- Uploaded PDFs: Page 18 of "Penetration-Testing-Guidance-v1_1.pdf" for methodologies; Page 7 of "Cybersecurity-best-practices-guide-2024-V2.pdf" for phishing (indirect vuln tie-in).

## Progression
Week 6 tested Week 3-5 hardenings (e.g., UFW blocked ports). Outputs inform Week 7 logging (monitor scan attempts).
