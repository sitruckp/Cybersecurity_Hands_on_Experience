# Week 8: Cloud Security Hands-On Experience

## Overview
Welcome to Week 8 of your cybersecurity learning plan! This week focuses on **Cloud Security**, a critical skill for SOC and Cybersecurity Analysts. Due to challenges with Docker and Apache2 on your Ubuntu 24.04.3 LTS server, we’ve adapted the plan to use a native web server setup (Apache2) with Nmap and Wireshark, avoiding Secure Boot or kernel module changes. This exercise simulates a cloud-hosted asset assessment using your lab: Ubuntu server as the target and Kali as the attacker/analyst workstation.

- **Date**: Monday, December 08, 2025
- **Status**: In progress—Apache2 restart failed; troubleshooting ongoing.

## Objectives
- Understand cloud security principles and simulate a cloud asset assessment ([NIST SP 800-53](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf), Control SC-7).
- Perform a vulnerability scan and analyze traffic on your Ubuntu server using Kali.
- Document findings and propose mitigations, reinforcing your Google Cybersecurity Certificate incident response skills.

## Prerequisites
- Ensure your Ubuntu server is updated:
  ```bash
  sudo apt update && sudo apt upgrade -y
  ```
- On Kali, ensure Nmap is installed:
  ```bash
  sudo apt install nmap -y
  ```
- Install Wireshark on Kali for traffic analysis:
  ```bash
  sudo apt install wireshark -y
  ```

## Core Exercises

### Exercise 1: Simulate a Cloud Asset with a Web Service
- **Scenario**: Set up a simple Apache2 web server on your Ubuntu server to mimic a cloud-hosted application.
- **Tools Used**:  
  - **Apache2**: A widely used web server for understanding application security in cloud environments ([CIS Controls v8, Control 3.1](https://www.cisecurity.org/controls/cis-controls-list)).
- **Steps**:  
  1. Install Apache2:
     ```bash
     sudo apt install apache2 -y
     ```
  2. Start the service:
     ```bash
     sudo systemctl start apache2
     sudo systemctl enable apache2
     ```
  3. Verify status:
     ```bash
     sudo systemctl status apache2
     ```
     *Expected Output*: "active (running)". Access locally with `curl localhost` to see the default page.
- **Current Status**: Installation succeeded, but `sudo systemctl restart apache2` failed due to a syntax error in `/etc/apache2/sites-enabled/000-default.conf` (see Troubleshooting).
- **Debrief**: Log the service status. Common pitfalls include config errors or unstarted services.

### Exercise 2: Vulnerability Scan with Nmap
- **Scenario**: Use Kali to scan your Ubuntu server’s web service, simulating a cloud asset assessment.
- **Tools Used**:  
  - **Nmap**: A network mapper for discovering hosts, services, and vulnerabilities ([MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)).
- **Steps**:  
  1. From Kali, scan your Ubuntu server’s IP (e.g., `192.168.1.168`):
     ```bash
     nmap -sV -p- <ubuntu_ip>
     ```
     *Simulated Output*: Port 80 (HTTP) open with Apache version.
  2. Run a vulnerability script:
     ```bash
     nmap -sV --script http-vuln* <ubuntu_ip>
     ```
     *Simulated Output*: May flag default pages or outdated versions.
- **Current Status**: Pending Apache restart. Log results once service is active.
- **Debrief**: Document open ports and vulnerabilities. Avoid external scanning.

### Exercise 3: Traffic Analysis with Wireshark
- **Scenario**: Monitor network traffic to your Ubuntu web server from Kali.
- **Tools Used**:  
  - **Wireshark**: A packet analyzer for security monitoring ([NIST SP 800-53, Control SI-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)).
- **Steps**:  
  1. On Kali, start Wireshark:
     ```bash
     wireshark &
     ```
  2. Select your interface and capture traffic.
  3. From Kali or Ubuntu, access the web server:
     ```bash
     curl <ubuntu_ip>
     ```
  4. Filter HTTP traffic in Wireshark (e.g., `http`) and analyze.
- **Current Status**: Pending Apache restart. Log HTTP details once operational.
- **Debrief**: Note headers and status codes. Watch for unencrypted traffic.

### Exercise 4: Apply Basic Mitigations
- **Scenario**: Harden the Apache server based on scan and traffic results.
- **Tools Used**:  
  - **Apache Configuration**: Secure the web server ([OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)).
- **Steps**:  
  1. Edit the config:
     ```bash
     sudo nano /etc/apache2/sites-available/000-default.conf
     ```
     Add `<Directory /var/www/html> Require local </Directory>` inside `<VirtualHost>`.
  2. Restart Apache:
     ```bash
     sudo systemctl restart apache2
     ```
  3. Rescan with Nmap to verify.
- **Current Status**: Restart failed due to syntax error (see Troubleshooting).
- **Debrief**: Log changes and re-scan results. Avoid config syntax errors.

### Exercise 5: Simulate a Cloud Incident Response
- **Scenario**: Triage a simulated breach on your web server.
- **Tools Used**:  
  - **Journalctl**: Logs for incident analysis ([NIST SP 800-53, Control SI-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)).
- **Steps**:  
  1. Check Apache logs:
     ```bash
     sudo tail -f /var/log/apache2/access.log
     ```
     *Sample Output*: Repeated requests from an IP.
  2. Check system logs:
     ```bash
     sudo journalctl -u apache2
     ```
  3. Document in an incident report (see Assessment).
- **Current Status**: Pending Apache restart. Log findings once active.
- **Debrief**: Note timestamps and actions. Avoid ignoring log rotation.

## Troubleshooting Apache2 Restart Failure
- **Issue**: `sudo systemctl restart apache2` failed with "Syntax error on line 29 of /etc/apache2/sites-enabled/000-default.conf: Require not allowed in <VirtualHost> context."
- **Fix**:  
  1. Edit the file:
     ```bash
     sudo nano /etc/apache2/sites-available/000-default.conf
     ```
     Move `Require local` into a `<Directory>` block:
     ```
     <VirtualHost *:80>
         ServerAdmin webmaster@localhost
         DocumentRoot /var/www/html
         <Directory /var/www/html>
             Require local
         </Directory>
         ErrorLog ${APACHE_LOG_DIR}/error.log
         CustomLog ${APACHE_LOG_DIR}/access.log combined
     </VirtualHost>
     ```
  2. Test config:
     ```bash
     sudo apache2ctl configtest
     ```
  3. Restart:
     ```bash
     sudo systemctl restart apache2
     sudo systemctl status apache2.service
     ```

## Resources
- [TryHackMe: Web Server Security](https://tryhackme.com/room/webserversecurity)  
- [SANS Web Application Security](https://www.sans.org/reading-room/whitepapers/application/web-application-security-testing-33841)  
- [Cyber-Handbook-Enterprise.pdf, Page 26](<DOCUMENT filename="Cyber-Handbook-Enterprise.pdf">) for Cloud Security Essentials (C|SE).