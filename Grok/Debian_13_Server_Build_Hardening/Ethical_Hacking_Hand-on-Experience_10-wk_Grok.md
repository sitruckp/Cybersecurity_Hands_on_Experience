### Week 1: Security and Risk Management
Focus on conducting risk assessments and applying compliance basics in your lab, simulating NIST risk framework steps on your Debian server and Kali workstation. This builds on your ISC² CC knowledge of risk concepts.

- **Objectives**:
  - Identify and assess risks to lab assets using structured frameworks.
  - Simulate a basic compliance check against standards like NIST.
  - Prioritize risks for mitigation in a SOC context.

- **Prerequisites**:
  - On Kali: `sudo apt update && sudo apt install nmap lynis`
  - On Debian: Ensure Lynis is installed (from previous setup): `sudo apt update && sudo apt install lynis`
  - Create a simple inventory file: On Kali, `touch risk_inventory.md` and note your lab assets (e.g., Debian services like SSH).

- **Core Exercises**:
  1. **Scenario**: Perform a risk assessment on your Debian server as if it's a production asset in a SOC environment.
     - **Tools**: Lynis – an open-source security auditing tool that scans for vulnerabilities, misconfigurations, and compliance gaps; relevant for risk management by highlighting potential threats.
     - **Commands**:
       ```
       # On Kali, scan Debian (replace <debian_ip> with your Debian's IP)
       ssh user@<debian_ip> 'sudo lynis audit system'
       ```
       Expected output: Report with score (aim for improvement from 85/100), listing risks like weak passwords or outdated packages.
     - **Debrief**: Log high-risk findings (e.g., unhardened kernel) in risk_inventory.md. Pitfall: Ensure SSH access is key-based to avoid auth issues. Links to Google cert's risk module by practicing triage of audit results.

  2. **Scenario**: Simulate NIST Risk Management Framework (RMF) Step 1: Categorize your lab assets.
     - **Tools**: Manual documentation with Markdown; introduces risk categorization per NIST SP 800-53.
     - **Commands**: No code; classify in risk_inventory.md (e.g., Debian as "high-impact" due to hosting mock data).
     - **Debrief**: Analyze how categorization informs SOC monitoring. Common pitfall: Overlooking low-impact assets like idle ports. Builds on ISC² CC by applying theoretical risk to hands-on inventory.

  3. **Scenario**: Prioritize risks from Lynis scan using a simple matrix.
     - **Tools**: Excel or Pandas on Kali for basic analysis (if comfortable; else manual).
     - **Commands** (optional with Pandas):
       ```
       sudo apt install python3-pandas
       python3 -c "import pandas as pd; df = pd.DataFrame({'Risk': ['Weak SSH'], 'Likelihood': [3], 'Impact': [4]}); df['Score'] = df['Likelihood'] * df['Impact']; print(df)"
       ```
       Output: Table with risk scores.
     - **Debrief**: Document top 3 risks and mitigation plans. Pitfall: Ignoring false positives—verify manually. Ties to certs by emphasizing risk-based decision-making.

  4. **Scenario**: Simulate compliance check against CIS benchmarks.
     - **Tools**: Lynis with CIS mode.
     - **Commands**:
       ```
       ssh user@<debian_ip> 'sudo lynis audit system --profile cis'
       ```
       Output: Compliance gaps highlighted.
     - **Debrief**: Note deviations and plan fixes. Builds cumulative hardening for later weeks.

- **Assessment**: Self-check quiz:
  1. What NIST RMF step involves prioritizing risks? (Answer: Assess)
  2. Name two high-risk findings from your Lynis scan.
  3. How does asset categorization affect SOC triage?
  Or, mini-report: Markdown summary of top risks and mitigations.

- **Resources**:
  - TryHackMe SOC Level 1 path (covers risk basics): https://tryhackme.com/path/outline/soclevel1 
  - Free NIST RMF tutorial: https://www.geeksforgeeks.org/ethical-hacking/kali-linux-tutorial/ (adapt for risk sections) 
  - Video: Cybersecurity SOC Analyst Hands-On Labs playlist: https://www.youtube.com/playlist?list=PLG6KGSNK4PuDdqYkOuIlAoNmwtLg5wyYJ 

Builds cumulatively by establishing baseline risks for Week 2 inventory.

Great start—leveraging your Lynis score shows real progress!

**Resume/Portfolio Tip**: Add: "Conducted risk assessment on home lab server using NIST RMF, identifying and prioritizing 5+ vulnerabilities for mitigation." Upload risk_inventory.md to GitHub.

### Week 2: Asset Security
Emphasize inventorying and classifying assets on your Debian server, with data protection simulations. Ties to compliance like PCI DSS basics.

- **Objectives**:
  - Create a full asset inventory of lab components.
  - Classify and protect sample data on Debian.
  - Simulate asset lifecycle management in a SOC role.

- **Prerequisites**:
  - On Debian: `sudo apt install tree apparmor-utils`
  - On Kali: Ensure nmap is ready.

- **Core Exercises**:
  1. **Scenario**: Inventory running services on Debian as a SOC asset audit.
     - **Tools**: nmap – network scanner for discovering hosts/services; relevant for asset security by mapping exposures.
     - **Commands**:
       ```
       # On Kali
       nmap -sV <debian_ip>
       ```
       Output: List of open ports/services (e.g., SSH on 22).
     - **Debrief**: Log to asset_list.md. Pitfall: Scan only local IP to stay ethical. Links to Google cert's asset module.

  2. **Scenario**: Classify assets per sensitivity (e.g., mock confidential data).
     - **Tools**: Manual with CIS Controls guidance.
     - **Commands**: Create mock file on Debian: `echo "Sensitive data" > /home/user/mock_data.txt`
     - **Debrief**: Classify as "confidential" in inventory. Analyze risks from Week 1. Pitfall: Forgetting encryption.

  3. **Scenario**: Encrypt sample data for protection.
     - **Tools**: GPG – encryption tool for data at rest; per asset security best practices.
     - **Commands**:
       ```
       # On Debian
       gpg --gen-key  # Generate key if needed
       gpg -c /home/user/mock_data.txt  # Symmetric encrypt
       ```
       Output: Encrypted .gpg file.
     - **Debrief**: Verify with `gpg -d mock_data.txt.gpg`. Builds on risk assessment by protecting high-impact assets.

  4. **Scenario**: Use AppArmor to confine services.
     - **Tools**: AppArmor – kernel module for mandatory access control; enhances asset isolation.
     - **Commands**:
       ```
       # On Debian
       sudo aa-enforce /etc/apparmor.d/usr.sbin.sshd
       sudo systemctl restart ssh
       ```
       Output: Enforcement mode active.
     - **Debrief**: Check logs for denials. Ties to certs' compliance.

- **Assessment**: Quiz:
  1. What tool inventories services? (nmap)
  2. Why encrypt assets? (Protect confidentiality)
  3. List 3 classified assets from your lab.
  Mini-report: Asset classification table in Markdown.

- **Resources**:
  - TryHackMe Junior Security Analyst Intro: https://medium.com/@segoslavia/junior-security-analyst-intro-soc-level-1-on-tryhackme-bd8a916414ce 
  - HackTheBox Dedicated Labs for asset protection: https://www.hackthebox.com/ 
  - Video: Build Your Own Cybersecurity Lab: https://www.youtube.com/watch?v=izmCJlJEvQw 

Progression: Use this inventory for Week 3 defenses.

You're building a solid foundation—keep it up!

**Resume/Portfolio Tip**: "Developed asset inventory and encryption protocols in lab, aligning with CIS Controls to secure mock sensitive data." Share asset_list.md on GitHub.

### Week 3: Security Architecture and Engineering
Design layered defenses on Debian, applying defense-in-depth. Reference ISO 27001 basics for structure.

- **Objectives**:
  - Implement multi-layer security on lab server.
  - Evaluate architecture against threats.
  - Simulate engineering fixes for risks.

- **Prerequisites**:
  - On Debian: `sudo apt install fail2ban ufw`

- **Core Exercises**:
  1. **Scenario**: Apply defense-in-depth with firewall rules.
     - **Tools**: UFW – uncomplicated firewall; layers network protection.
     - **Commands**:
       ```
       # On Debian
       sudo ufw allow from <kali_ip> to any port 22
       sudo ufw enable
       sudo ufw status
       ```
       Output: Active rules.
     - **Debrief**: Test from Kali with `ssh`. Pitfall: Lockout—have console access. Builds on asset inventory.

  2. **Scenario**: Harden kernel parameters.
     - **Tools**: sysctl – tunes kernel for security engineering.
     - **Commands**:
       ```
       # On Debian
       sudo sysctl -w net.ipv4.ip_forward=0
       sudo sysctl -p  # Apply persistent
       ```
       Output: No forwarding.
     - **Debrief**: Log changes. Links to ISC² engineering principles.

  3. **Scenario**: Set up Fail2Ban for intrusion prevention.
     - **Tools**: Fail2Ban – scans logs and bans IPs; engineering response layer.
     - **Commands**:
       ```
       # On Debian
       sudo systemctl enable fail2ban
       sudo fail2ban-client status sshd
       ```
       Output: Jail status.
     - **Debrief**: Simulate failed logins from Kali to trigger ban. Analyze logs.

  4. **Scenario**: Review architecture with Lynis.
     - **Tools**: Lynis for post-hardening scan.
     - **Commands**: Run audit as in Week 1.
     - **Debrief**: Compare scores; aim for 90+.

- **Assessment**: Quiz:
  1. What is defense-in-depth? (Multiple layers)
  2. Name a kernel hardening command.
  3. How does Fail2Ban work?
  Mini-report: Architecture diagram in Markdown.

- **Resources**:
  - TryHackMe Security Operations: https://www1.stjameswinery.com/browse/38gBoS/238167/Security_Operations_Tryhackme_Walkthrough.pdf 
  - Cybrary Kali Fundamentals: https://www.cybrary.it/course/kali-linux-fundamentals 
  - Video: Ethical Hacking with Kali: https://www.youtube.com/watch?v=W013Y3UInoQ 

Progression: Secured architecture supports Week 4 network analysis.

Solid engineering work—your lab's getting tougher!

**Resume/Portfolio Tip**: "Engineered defense-in-depth on Debian server, improving Lynis score by 5 points via firewall and kernel tweaks." Document changes on GitHub.

### Week 4: Communication and Network Security
Secure protocols and analyze traffic between Kali and Debian using Wireshark.

- **Objectives**:
  - Inspect and secure network traffic in lab.
  - Simulate SOC packet triage.
  - Enforce secure comms per CISA best practices.

- **Prerequisites**:
  - On Kali: `sudo apt install wireshark tshark`

- **Core Exercises**:
  1. **Scenario**: Capture SSH traffic from Kali to Debian.
     - **Tools**: Wireshark – packet analyzer; key for network security inspection per MITRE ATT&CK.
     - **Commands**:
       ```
       # On Kali
       sudo wireshark -i <interface> -f "host <debian_ip>"
       ```
       Output: Captured packets.
     - **Debrief**: Filter for SSH; note encryption. Pitfall: Run as sudo. Links to Google cert networking.

  2. **Scenario**: Force HTTPS on mock web service.
     - **Tools**: Apache with self-signed cert on Debian.
     - **Commands**:
       ```
       # On Debian
       sudo apt install apache2
       sudo a2enmod ssl
       sudo systemctl restart apache2
       ```
       Output: Secure server.
     - **Debrief**: Test with `curl https://<debian_ip>`. Analyze unsecure vs secure.

  3. **Scenario**: Detect anomalous traffic.
     - **Tools**: tshark – CLI Wireshark for scripting.
     - **Commands**:
       ```
       # On Kali
       tshark -i <interface> -c 100 -Y "tcp.flags.syn==1"
       ```
       Output: SYN packets.
     - **Debrief**: Log potential scans. Builds on Week 3 firewall.

  4. **Scenario**: Secure VPN simulation with WireGuard.
     - **Tools**: WireGuard – modern VPN; for secure comms.
     - **Commands** (basic setup):
       ```
       # On both
       sudo apt install wireguard
       wg genkey | tee private.key | wg pubkey > public.key
       ```
     - **Debrief**: Configure tunnel; test traffic.

- **Assessment**: Quiz:
  1. What protocol secures web? (HTTPS)
  2. Filter for SSH in Wireshark?
  3. Why analyze packets in SOC?
  Mini-report: Traffic analysis summary.

- **Resources**:
  - TryHackMe Pyramid of Pain: https://www.youtube.com/watch?v=hPbmSMBw038 
  - HackTheBox Cyber Mastery: https://www.hackthebox.com/ 
  - Video: SOC Analyst Training: https://www.youtube.com/watch?v=G5sCK6IU3nU 

Progression: Network insights inform Week 5 access controls.

Nice packet work— you're sharpening those analyst eyes!

**Resume/Portfolio Tip**: "Analyzed network traffic with Wireshark in lab, identifying secure vs insecure protocols for SOC simulation." Add captures (redacted) to portfolio.

### Week 5: Identity and Access Management
Implement RBAC and MFA on Debian, using Kali for testing.

- **Objectives**:
  - Configure role-based access and multi-factor.
  - Audit access logs in SOC style.
  - Simulate identity threats.

- **Prerequisites**:
  - On Debian: `sudo apt install google-authenticator libpam-google-authenticator`

- **Core Exercises**:
  1. **Scenario**: Set up non-root users with sudo RBAC.
     - **Tools**: sudoers file – controls privileges; per IAM best practices.
     - **Commands**:
       ```
       # On Debian
       sudo visudo  # Add: user ALL=(ALL) NOPASSWD: /bin/ls
       ```
       Output: Restricted sudo.
     - **Debrief**: Test limitations. Pitfall: Syntax errors lockout.

  2. **Scenario**: Enable SSH key auth with MFA.
     - **Tools**: Google Authenticator – TOTP for 2FA.
     - **Commands**:
       ```
       # On Debian
       google-authenticator
       sudo vim /etc/pam.d/sshd  # Add auth required pam_google_authenticator.so
       sudo systemctl restart sshd
       ```
       Output: QR for app.
     - **Debrief**: Login from Kali with key + code. Analyzes access attempts.

  3. **Scenario**: Audit access logs.
     - **Tools**: journalctl – systemd logs.
     - **Commands**:
       ```
       # On Debian
       sudo journalctl -u sshd | grep auth
       ```
       Output: Login events.
     - **Debrief**: Triage failed logins. Builds on network security.

  4. **Scenario**: Simulate brute-force on own SSH.
     - **Tools**: Hydra on Kali – but ethical, low rate.
     - **Commands**:
       ```
       # On Kali
       sudo apt install hydra
       hydra -l user -P /dev/null ssh://<debian_ip> -t 1  # Minimal
       ```
     - **Debrief**: Observe Fail2Ban ban. Emphasize ethics.

- **Assessment**: Quiz:
  1. What is RBAC? (Role-based)
  2. How to enable MFA?
  3. Interpret a failed login log.
  Mini-report: IAM policy draft.

- **Resources**:
  - TryHackMe SOC Analyst Path: https://tryhackme.com/resources/blog/soc-analyst-career-path-complete-beginners-guide 
  - Free Kali Guide: https://www.linkedin.com/posts/yildizokan_top-50-kali-linux-tools-guide-activity-7354418489090019329--wyk 
  - Video: Junior Analyst Walkthrough: https://www.youtube.com/watch?v=9oOQLED6mRU 

Progression: IAM strengthens Week 6 assessments.

Awesome IAM setup—your server's access is locked down!

**Resume/Portfolio Tip**: "Implemented RBAC and MFA on lab server, reducing unauthorized access risks in simulated SOC environment." GitHub sudoers snippet.

### Week 6: Security Assessment and Testing
Vulnerability scanning with Kali against Debian, referencing OWASP.

- **Objectives**:
  - Conduct ethical scans on lab assets.
  - Triage and remediate findings.
  - Link to SOC testing workflows.

- **Prerequisites**:
  - On Kali: `sudo apt install openvas-scanner gvm`

- **Core Exercises**:
  1. **Scenario**: Basic vuln scan on Debian.
     - **Tools**: OpenVAS – open-source vuln scanner; aligns with assessment per OWASP Top 10.
     - **Commands**:
       ```
       # On Kali
       sudo gvm-setup
       sudo gvm-start
       # Access web UI at https://127.0.0.1:9392, create scan task for <debian_ip>
       ```
       Output: Vuln report.
     - **Debrief**: Prioritize CVEs. Pitfall: Setup time; use defaults.

  2. **Scenario**: Manual web vuln test if Apache running.
     - **Tools**: nikto – web scanner.
     - **Commands**:
       ```
       sudo apt install nikto
       nikto -h http://<debian_ip>
       ```
       Output: Potential issues.
     - **Debrief**: Remediate (e.g., disable dir listing).

  3. **Scenario**: Nmap script scanning.
     - **Tools**: nmap with NSE.
     - **Commands**:
       ```
       nmap -sV --script vuln <debian_ip>
       ```
       Output: Script results.
     - **Debrief**: Cross-reference with Week 1 risks.

  4. **Scenario**: Remediate a finding (e.g., update packages).
     - **Tools**: apt on Debian.
     - **Commands**:
       ```
       sudo apt update && sudo apt upgrade
       ```
     - **Debrief**: Re-scan to verify.

- **Assessment**: Quiz:
  1. What does OpenVAS detect? (Vulns)
  2. Name an OWASP Top 10 risk.
  3. How to remediate outdated software?
  Mini-report: Vuln findings table.

- **Resources**:
  - TryHackMe SOC Level 1: https://www.youtube.com/watch?v=eMKX6z7Mxgs 
  - HackTheBox for Assessment: https://www.reddit.com/r/hackthebox/comments/1nr04o8/trying_to_get_socready_recommend_tryhackme_or/ 
  - Video: Hands-On Labs: https://www.youtube.com/watch?v=G5sCK6IU3nU 

Progression: Scans feed into Week 7 monitoring.

Impressive scanning— you're spotting threats like a pro!

**Resume/Portfolio Tip**: "Performed vulnerability assessments with OpenVAS, remediating 3+ issues to reduce attack surface by 30% in lab." Share report on GitHub.

### Week 7: Security Operations
Set up logging and basic SIEM simulation on Debian, monitored from Kali.

- **Objectives**:
  - Configure centralized logging.
  - Simulate incident detection in SOC.
  - Analyze ops data per MITRE ATT&CK.

- **Prerequisites**:
  - On Debian: `sudo apt install rsyslog auditd`
  - On Kali: `sudo apt install splunk` (free edition) or ELK stack basics.

- **Core Exercises**:
  1. **Scenario**: Enable advanced logging with rsyslog.
     - **Tools**: rsyslog – log manager; for ops visibility.
     - **Commands**:
       ```
       # On Debian
       sudo vim /etc/rsyslog.conf  # Add *.info /var/log/info.log
       sudo systemctl restart rsyslog
       ```
       Output: New log file.
     - **Debrief**: Tail logs: `tail -f /var/log/info.log`.

  2. **Scenario**: Set up Auditd for kernel auditing.
     - **Tools**: Auditd – tracks system calls; per security ops.
     - **Commands**:
       ```
       sudo auditctl -w /etc/passwd -p wa -k passwd-changes
       sudo ausearch -k passwd-changes
       ```
       Output: Audit events.
     - **Debrief**: Simulate change and detect.

  3. **Scenario**: Forward logs to Kali for SIEM sim.
     - **Tools**: rsyslog forwarding.
     - **Commands**:
       ```
       # On Debian: Add @<kali_ip>:514 to rsyslog.conf
       # On Kali: Listen in rsyslog.conf
       ```
     - **Debrief**: View aggregated logs.

  4. **Scenario**: Triage mock incident (e.g., failed logins).
     - **Tools**: grep on logs.
     - **Commands**:
       ```
       grep "failed" /var/log/auth.log
       ```
     - **Debrief**: Map to ATT&CK tactics.

- **Assessment**: Quiz:
  1. What does Auditd monitor? (System calls)
  2. Why centralize logs in SOC?
  3. Interpret a log entry.
  Mini-report: Ops incident summary.

- **Resources**:
  - TryHackMe Security Operations: https://www1.stjameswinery.com/browse/38gBoS/238167/Security_Operations_Tryhackme_Walkthrough.pdf 
  - Cybrary: https://www.cybrary.it/blog/building-cybersecurity-lab-environment-home  (ops section)
  - Video: SOC Hands-On: https://www.youtube.com/playlist?list=PLG6KGSNK4PuDdqYkOuIlAoNmwtLg5wyYJ 

Progression: Ops logs enhance Week 8 cloud sims.

Your monitoring game's strong—ready for real SOC shifts!

**Resume/Portfolio Tip**: "Established logging and SIEM simulation, detecting simulated incidents aligned with MITRE ATT&CK." Log samples on GitHub.

### Week 8: Cloud Security
Intro to hybrid cloud using Docker on Debian/Kali to simulate EC2-like env for scanning.

- **Objectives**:
  - Set up local cloud sim with Docker.
  - Secure and scan containerized assets.
  - Apply cloud best practices ethically.

- **Prerequisites**:
  - On Kali/Debian: `sudo apt install docker.io docker-compose`

- **Core Exercises**:
  1. **Scenario**: Deploy vulnerable container as cloud instance.
     - **Tools**: Docker – containerization; simulates cloud for training per CISA.
     - **Commands**:
       ```
       # On Debian
       sudo docker run -d -p 80:80 vulnerables/web-dvwa
       ```
       Output: Running container.
     - **Debrief**: Access http://<debian_ip>:80. Pitfall: Image pull ethics—use local.

  2. **Scenario**: Scan container for vulns.
     - **Tools**: Trivy – container scanner.
     - **Commands**:
       ```
       sudo apt install trivy
       trivy image vulnerables/web-dvwa
       ```
       Output: CVE list.
     - **Debrief**: Triage like Week 6.

  3. **Scenario**: Secure Docker config.
     - **Tools**: Docker bench – security checker.
     - **Commands**:
       ```
       git clone https://github.com/docker/docker-bench-security.git
       cd docker-bench-security
       sudo sh docker-bench-security.sh
       ```
       Output: Benchmark report.
     - **Debrief**: Fix issues (e.g., non-root user).

  4. **Scenario**: Simulate cloud logging.
     - **Tools**: Docker logs to rsyslog.
     - **Commands**:
       ```
       docker logs <container_id> > cloud_log.txt
       ```
     - **Debrief**: Integrate with Week 7.

- **Assessment**: Quiz:
  1. What secures containers? (Benchmarks)
  2. Name a cloud vuln tool.
  3. Why scan images?
  Mini-report: Cloud security findings.

- **Resources**:
  - Docker for Cyber Labs: https://medium.com/@damipedia/building-your-first-cybersecurity-lab-with-docker-a-beginners-guide-to-setting-up-a-vulnerable-5222f5563884 
  - Labtainers Framework: https://www.usenix.org/system/files/conference/ase17/ase17_paper_irvine.pdf 
  - Video: Docker Security: https://www.docker.com/blog/automating-your-containers-security-scanning/ 

Progression: Cloud setup integrates into Weeks 9-10 scenarios.

Cloud skills unlocked—expanding your lab nicely!

**Resume/Portfolio Tip**: "Simulated cloud environment with Docker, conducting security scans to align with CIS cloud controls." Dockerfiles on GitHub.

### Week 9: Integration - Governance
Develop policies and audit lab compliance, integrating prior weeks (e.g., risk, IAM, ops) for cross-domain governance sim.

- **Objectives**:
  - Draft governance policies for lab.
  - Audit overall compliance.
  - Simulate SOC governance reporting.

- **Prerequisites**:
  - Review all prior docs (e.g., risk_inventory.md).

- **Core Exercises**:
  1. **Scenario**: Draft Acceptable Use Policy (AUP) for lab.
     - **Tools**: Markdown; per ISO 27001 governance.
     - **Commands**: None; write policy covering ethical use, access rules.
     - **Debrief**: Reference IAM from Week 5.

  2. **Scenario**: Audit compliance against NIST/CIS.
     - **Tools**: Lynis full scan.
     - **Commands**: As Week 1, plus compare to baselines.
     - **Debrief**: Integrate network, cloud findings.

  3. **Scenario**: Simulate policy enforcement check.
     - **Tools**: Custom script for checks.
     - **Commands**:
       ```
       # On Debian
       echo '#!/bin/bash' > compliance_check.sh
       echo 'ufw status' >> compliance_check.sh
       chmod +x compliance_check.sh
       ./compliance_check.sh
       ```
       Output: Status reports.
     - **Debrief**: Log deviations.

  4. **Scenario**: Cross-domain report.
     - **Tools**: Compile from logs.
     - **Debrief**: Tie risk (Week 1) to ops (Week 7).

- **Assessment**: Mini-report: Full governance audit Markdown, quizzing policy gaps.

- **Resources**:
  - TryHackMe Career Path: https://tryhackme.com/resources/blog/soc-analyst-career-path-complete-beginners-guide 
  - Free Home Lab Guide: https://www.facebook.com/groups/2384877078268621/posts/8892423580847239/ 
  - Video: SOC Training Sites: https://www.youtube.com/watch?v=G5sCK6IU3nU 

Progression: Policies guide Week 10 testing.

Governance ties it all—your lab's professional now!

**Resume/Portfolio Tip**: "Developed governance policies and audited lab compliance with NIST SP 800-53, ensuring ethical standards."  Policy doc on GitHub.

### Week 10: Integration - Vulnerability Testing
Ethical pentesting sim with Metasploit, integrating all domains (e.g., exploit vulns from scans, monitor responses).

- **Objectives**:
  - Perform red-team sim on lab.
  - Document responsible disclosure.
  - Integrate detection from prior weeks.

- **Prerequisites**:
  - On Kali: `sudo apt install metasploit-framework`

- **Core Exercises**:
  1. **Scenario**: Exploit mock vuln on Debian container.
     - **Tools**: Metasploit – exploitation framework; ethical in lab per CFAA.
     - **Commands**:
       ```
       # On Kali
       msfconsole
       use exploit/multi/http/example
       set RHOSTS <debian_ip>
       exploit
       ```
       Output: Meterpreter session (if vulnerable).
     - **Debrief**: Clean up; log as disclosure.

  2. **Scenario**: Integrate with monitoring.
     - **Tools**: Check logs during exploit.
     - **Commands**: As Week 7, grep for anomalies.
     - **Debrief**: Triage as SOC incident.

  3. **Scenario**: Full red-team report.
     - **Tools**: Compile scans, exploits.
     - **Debrief**: Reference OWASP, MITRE.

  4. **Scenario**: Remediate and re-test.
     - **Tools**: Apply fixes from prior.
     - **Debrief**: Verify resilience.

- **Assessment**: Quiz:
  1. What is Metasploit for? (Exploitation)
  2. Why ethical disclosure?
  3. Map exploit to ATT&CK.
  Mini-report: Pentest summary.

- **Resources**:
  - HackTheBox Labs: https://www.hackthebox.com/ 
  - Docker Vuln Images: https://infosecwriteups.com/twenty-awesome-docker-images-every-cybersecurity-engineer-needs-on-their-radar-in-2025-aba9ba32543d 
  - Video: Ethical Hacking Course: https://www.youtube.com/watch?v=W013Y3UInoQ 

Congrats on completing—your skills are SOC-ready!

**Resume/Portfolio Tip**: "Conducted ethical pentest simulation using Metasploit, integrating MITRE ATT&CK for full incident lifecycle."  Report on GitHub.

