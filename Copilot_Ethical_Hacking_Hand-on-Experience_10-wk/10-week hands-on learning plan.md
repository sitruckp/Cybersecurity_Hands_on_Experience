# 10-week soc analyst hands-on learning plan for your kali + debian lab

You’ve already done the hard part—setting up a safe, isolated lab and earning solid credentials. This plan turns that foundation into practical, portfolio-ready SOC skills. Every activity is strictly ethical and confined to your own lab. Keep notes and screenshots as you go; we’ll add resume-ready outputs weekly.

---

## Week 1: Security and risk management

### Objectives
- **Perform a basic risk assessment:** Identify threats, vulnerabilities, and controls for your Debian server and Kali workstation.
- **Map controls to standards:** Align at least five current hardening measures to NIST SP 800-53 and CIS Controls.
- **Create a risk register:** Document risks with likelihood/impact and treatment plans.

### Prerequisites
- **Kali:**  
  ```
  sudo apt update && sudo apt install lynis nmap jq
  ```
- **Debian:**  
  ```
  sudo apt update && sudo apt install lynis unattended-upgrades apt-show-versions
  ```

### Core exercises
- **Exercise 1 — Baseline posture check with Lynis (Debian)**
  - **Scenario:** Measure current hardening to identify risk drivers.
  - **Tools used:** Lynis (host security auditing).
  - **Commands:**  
    ```
    sudo lynis audit system | tee ~/lynis_$(date +%F).log
    grep -E "Hardening index|Warnings|Suggestions" ~/lynis_*.log
    ```
  - **Debrief:** Export key warnings (e.g., missing log rotation, weak SSH settings). Map each to a control (e.g., audit/logging → NIST AU; SSH hardening → AC). Note current Lynis score and define a target improvement.

- **Exercise 2 — Threat modeling mini-workshop**
  - **Scenario:** Identify top risks for your lab (e.g., credential theft, misconfigurations).
  - **Tools used:** Simple STRIDE framework (Spoofing/Tampering/Repudiation/Information disclosure/Denial of service/Elevation of privilege).
  - **Steps:**  
    - **Identify assets:** Debian services (SSH, rsyslog), data files, syslogs.  
    - **Identify trust boundaries:** SSH ingress, local admin actions, package repos.  
    - **Document STRIDE per asset:** One-liner per risk and proposed control (e.g., Information disclosure → enforce SSH strong ciphers).
  - **Debrief:** Prioritize top 5 risks by likelihood/impact and assign treatment (accept/mitigate/transfer/avoid).

- **Exercise 3 — Control mapping to NIST/CIS**
  - **Scenario:** Connect your current configurations to recognized frameworks.
  - **Tools used:** NIST SP 800-53 categories (AC, AU, CM, IA, SI) and CIS Controls v8.
  - **Steps:** Make a small table: control, your implementation, standard reference, evidence (command, config path).
  - **Debrief:** Validate evidence artifacts (e.g., `/etc/ssh/sshd_config`, `ufw status`). Note gaps for future weeks.

### Assessment
- **Mini report (Markdown):** Asset overview, risks (5), controls mapped (5+), timeline to remediate, Lynis score before/after.
- **Quiz:**  
  - **Q1:** What’s the difference between a threat and a vulnerability?  
  - **Q2:** Which NIST control family covers log integrity?  
  - **Q3:** What’s a risk treatment plan and why document it?  
  - **Q4:** Provide one STRIDE example for SSH.  

### Resources
- NIST SP 800-53 (Control families overview): https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final  
- CIS Controls v8: https://www.cisecurity.org/controls/cis-controls  
- CISA risk management primers: https://www.cisa.gov/resources-tools/resources/risk-management

### Portfolio tip
- **Add this:** “Performed lab risk assessment; mapped 7 controls to NIST/CIS; established remediation plan increasing Lynis score baseline visibility.”

---

## Week 2: Asset security

### Objectives
- **Build an asset inventory:** Enumerate Debian services, ports, packages.
- **Classify and protect data:** Create sample sensitive data and encrypt at rest/in transit.
- **Establish configuration baselines:** Document and verify system settings.

### Prerequisites
- **Kali:**  
  ```
  sudo apt update && sudo apt install nmap openvpn wireshark
  ```
- **Debian:**  
  ```
  sudo apt update && sudo apt install openssl gnupg coreutils
  ```

### Core exercises
- **Exercise 1 — Service/port inventory (Kali → Debian)**
  - **Scenario:** Scan your Debian server from Kali to inventory exposed surfaces.
  - **Tools used:** Nmap (network scanner).
  - **Commands:**  
    ```
    nmap -sV -p- -T4 <DEBIAN_IP> -oN inventory_full.txt
    nmap --script vuln -p 22,80,443 <DEBIAN_IP> -oN inventory_vuln.txt
    ```
  - **Debrief:** Catalog services, versions, and non-essential ports. Align to CIS Control: inventory and control of enterprise assets.

- **Exercise 2 — Data classification and encryption (Debian)**
  - **Scenario:** Create sample “confidential” and “public” data and encrypt confidential files.
  - **Tools used:** OpenSSL (file encryption), GPG (key-based encryption).
  - **Commands:**  
    ```
    echo "CONFIDENTIAL: <REDACTED>" > confidential.txt
    openssl enc -aes-256-cbc -salt -in confidential.txt -out confidential.enc
    gpg --full-generate-key
    gpg -e -r "<ALIAS>" confidential.txt
    ```
  - **Debrief:** Store keys safely, document classification labels and handling rules.

- **Exercise 3 — Baseline configuration check**
  - **Scenario:** Record critical config files and create hashes for integrity checks.
  - **Tools used:** sha256sum.
  - **Commands:**  
    ```
    sudo sha256sum /etc/ssh/sshd_config /etc/rsyslog.conf /etc/sysctl.conf > config_baseline.sha256
    ```
  - **Debrief:** Explain how baselines detect unauthorized changes; plan weekly verification.

### Assessment
- **Checklist:** Inventory (services/ports), data classes (2+), encryption evidence (commands/outputs), baseline hash file.
- **Quiz:**  
  - **Q1:** Why classify data before choosing controls?  
  - **Q2:** Which risks arise if baseline hashes are not maintained?  
  - **Q3:** What does `-sV` do in Nmap?

### Resources
- OWASP Top 10 (data protection context): https://owasp.org/www-project-top-ten/  
- NIST SP 800-171 (protecting controlled data): https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final  
- SANS cheat sheets: https://www.sans.org/blog/sans-cheat-sheets/

### Portfolio tip
- **Add this:** “Built asset inventory and encryption workflow; implemented configuration baselines for integrity monitoring.”

---

## Week 3: Security architecture and engineering

### Objectives
- **Design defense-in-depth:** Layer controls across network, host, and application.
- **Harden SSH and kernel settings:** Apply secure ciphers, banners, and sysctl.
- **Document architecture diagram:** Visualize trust boundaries and control layers.

### Prerequisites
- **Debian:**  
  ```
  sudo apt install ufw fail2ban
  ```
- **Kali:** No additional tools required.

### Core exercises
- **Exercise 1 — SSH hardening (Debian)**
  - **Scenario:** Reduce attack surface and enforce strong cryptography.
  - **Tools used:** SSH daemon configuration.
  - **Commands:**  
    ```
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
    sudo nano /etc/ssh/sshd_config
    # Set:
    # PermitRootLogin no
    # PasswordAuthentication no
    # KexAlgorithms curve25519-sha256@libssh.org
    # Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    # MACs hmac-sha2-512,hmac-sha2-256
    sudo systemctl restart ssh
    ```
  - **Debrief:** Confirm connectivity via keys; log authentication attempts in `/var/log/auth.log`.

- **Exercise 2 — UFW and Fail2ban layered controls**
  - **Scenario:** Combine network filtering with dynamic bans.
  - **Tools used:** UFW, Fail2ban.
  - **Commands:**  
    ```
    sudo ufw default deny incoming
    sudo ufw allow 22/tcp
    sudo ufw enable
    sudo systemctl status ufw

    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo nano /etc/fail2ban/jail.local
    # [sshd]
    # enabled = true
    # port    = 22
    # logpath = /var/log/auth.log
    # maxretry = 4
    sudo systemctl restart fail2ban
    sudo fail2ban-client status sshd
    ```
  - **Debrief:** Trigger test failed logins from Kali and verify bans.

- **Exercise 3 — Architecture diagram**
  - **Scenario:** Draw your lab topology and control layers.
  - **Tools used:** Any diagramming tool (text-based notes acceptable).
  - **Steps:** Show Kali → Debian via SSH; indicate UFW, Fail2ban, SSH crypto, sysctl. Include logging path.

### Assessment
- **Mini report:** Before/after configs, test evidence (logs/screens), diagram image or ASCII map.
- **Quiz:**  
  - **Q1:** Explain defense-in-depth in your lab context.  
  - **Q2:** What risk does `PasswordAuthentication no` mitigate?  
  - **Q3:** How do Fail2ban and UFW complement each other?

### Resources
- NIST SP 800-160 (systems security engineering): https://csrc.nist.gov/publications/detail/sp/800-160/vol-1/final  
- CIS Benchmarks for Debian: https://www.cisecurity.org/benchmarks  
- CISA SSH hardening guidance: https://www.cisa.gov/resources-tools/resources/secure-shell-ssh

### Portfolio tip
- **Add this:** “Implemented defense-in-depth: SSH crypto hardening, UFW, Fail2ban; documented architecture and controls.”

---

## Week 4: Communication and network security

### Objectives
- **Capture and analyze traffic:** Use Wireshark/tcpdump for protocol insights.
- **Validate secure protocols:** Confirm SSH, TLS behavior and identify insecure traffic.
- **Document findings:** Produce packet-level evidence tied to controls.

### Prerequisites
- **Kali:**  
  ```
  sudo apt install wireshark tshark tcpdump openssl
  sudo usermod -a -G wireshark $USER && newgrp wireshark
  ```
- **Debian:**  
  ```
  sudo apt install openssl
  ```

### Core exercises
- **Exercise 1 — Packet capture of SSH**
  - **Scenario:** Observe SSH handshake and encrypted session.
  - **Tools used:** Wireshark/tcpdump.
  - **Commands (Kali):**  
    ```
    sudo tcpdump -i <IFACE> host <DEBIAN_IP> and port 22 -w ssh_capture.pcap
    ssh <USER>@<DEBIAN_IP> "echo hello"
    ```
  - **Debrief:** Inspect pcap in Wireshark; confirm no plaintext credentials; note key exchange and cipher suite.

- **Exercise 2 — Self-signed TLS and inspection**
  - **Scenario:** Generate TLS cert on Debian and test from Kali.
  - **Tools used:** OpenSSL.
  - **Commands (Debian):**  
    ```
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=lab.local"
    openssl s_server -cert cert.pem -key key.pem -accept 4433 -www
    ```
    (Kali)  
    ```
    openssl s_client -connect <DEBIAN_IP>:4433 -tls1_2 -servername lab.local
    ```
  - **Debrief:** Review cert details, TLS version, and cipher; capture with Wireshark and document secure negotiation.

- **Exercise 3 — Identify insecure protocol usage**
  - **Scenario:** Compare SSH vs. a plaintext service (e.g., netcat banner).
  - **Commands (Debian):**  
    ```
    sudo apt install netcat-openbsd
    printf "WELCOME\n" | nc -l -p 2323
    ```
    (Kali capture):  
    ```
    sudo tcpdump -i <IFACE> host <DEBIAN_IP> and port 2323 -A -vv
    ```
  - **Debrief:** Show plaintext content; justify blocking insecure services.

### Assessment
- **Packet analysis report:** Screenshots of SSH and TLS handshakes; plaintext demonstration; recommended controls.
- **Quiz:**  
  - **Q1:** Why is SSH traffic unreadable in Wireshark after handshake?  
  - **Q2:** What does `-A` do in tcpdump?  
  - **Q3:** Which TLS attributes confirm modern security?

### Resources
- OWASP TLS cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html  
- SANS Wireshark tips: https://www.sans.org/blog/wireshark-tips/  
- NIST SP 800-52r2 (TLS guidance): https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final

### Portfolio tip
- **Add this:** “Performed protocol analysis; validated secure SSH/TLS; documented insecure plaintext risks and mitigations.”

---

## Week 5: Identity and access management

### Objectives
- **Implement least privilege:** Configure sudoers and groups.
- **Strengthen SSH access:** Enforce keys, banners, and MFA with Google PAM or Duo (local-only).
- **Audit authentication logs:** Detect and triage failed login attempts.

### Prerequisites
- **Debian:**  
  ```
  sudo apt install libpam-google-authenticator
  ```
- **Kali:** No new tools.

### Core exercises
- **Exercise 1 — Sudoers and RBAC**
  - **Scenario:** Create roles and limit commands.
  - **Tools used:** `/etc/sudoers`, groups.
  - **Commands (Debian):**  
    ```
    sudo adduser analyst
    sudo usermod -aG sudo analyst
    sudo visudo
    # %analysts ALL=(ALL) /usr/bin/systemctl status, /usr/bin/journalctl
    ```
  - **Debrief:** Demonstrate allowed vs. denied commands; log entries in `/var/log/auth.log`.

- **Exercise 2 — SSH key-only + login banner**
  - **Scenario:** Enforce key auth and present a legal banner.
  - **Commands (Debian):**  
    ```
    echo "Authorized access only. Activity monitored." | sudo tee /etc/issue.net
    sudo nano /etc/ssh/sshd_config
    # PasswordAuthentication no
    # PermitRootLogin no
    # Banner /etc/issue.net
    sudo systemctl restart ssh
    ```
  - **Debrief:** Connect from Kali with key; capture banner display.

- **Exercise 3 — PAM-based MFA (Google Authenticator)**
  - **Scenario:** Add TOTP MFA for SSH.
  - **Commands (Debian):**  
    ```
    sudo nano /etc/pam.d/sshd
    # Add:
    # auth required pam_google_authenticator.so nullok
    sudo nano /etc/ssh/sshd_config
    # ChallengeResponseAuthentication yes
    sudo systemctl restart ssh
    sudo -u analyst google-authenticator -t -d -f -r 3 -R 30 -W
    ```
  - **Debrief:** Test SSH login requiring TOTP; store emergency codes securely.

### Assessment
- **Checklist:** Sudoers role proof, banner screenshot, MFA login evidence.
- **Quiz:**  
  - **Q1:** What principle does limiting sudo commands enforce?  
  - **Q2:** Why use banners in SSH?  
  - **Q3:** How does PAM integrate MFA with SSH?

### Resources
- NIST SP 800-63 (digital identity): https://pages.nist.gov/800-63-3/  
- CIS Controls (access control): https://www.cisecurity.org/controls  
- CISA identity security guidance: https://www.cisa.gov/topics/identity-credential-and-access-management

### Portfolio tip
- **Add this:** “Implemented least privilege and SSH MFA; enhanced auth auditing and access controls.”

---

## Week 6: Security assessment and testing

### Objectives
- **Run authenticated and unauthenticated scans:** Compare findings.
- **Validate false positives:** Manually verify vulnerabilities.
- **Produce a concise remediation plan.**

### Prerequisites
- **Kali:**  
  ```
  sudo apt update && sudo apt install openvas
  gvm-setup
  gvm-check-setup
  ```
- **Debian:** Ensure test user exists for authenticated scans.

### Core exercises
- **Exercise 1 — OpenVAS unauthenticated scan**
  - **Scenario:** Baseline external-facing issues.
  - **Tools used:** OpenVAS/GVM (vulnerability scanner).
  - **Steps:** Create target (Debian IP); run full fast scan; export results (PDF/CSV).
  - **Debrief:** Focus on high/critical findings; correlate with earlier hardening.

- **Exercise 2 — Authenticated scan comparison**
  - **Scenario:** Deeper host insights via SSH creds.
  - **Steps:** Configure SSH login in GVM; rerun; compare deltas with unauthenticated scan.
  - **Debrief:** Explain why authenticated scans reveal patch/config issues.

- **Exercise 3 — Manual validation**
  - **Scenario:** Validate one finding (e.g., weak TLS, outdated package).
  - **Commands (Debian):**  
    ```
    apt-show-versions | grep "upgradeable"
    openssl s_client -connect <DEBIAN_IP>:4433 -tls1_2 -servername lab.local
    ```
  - **Debrief:** Mark verified vs. false positive; propose fixes.

### Assessment
- **Mini report:** Scan methodology, key findings, validation notes, remediation tasks with owner/date.
- **Quiz:**  
  - **Q1:** Why are authenticated scans important?  
  - **Q2:** Name a common false positive source.  
  - **Q3:** What’s your process for verifying a vulnerability?

### Resources
- OWASP testing guide: https://owasp.org/www-project-web-security-testing-guide/  
- SANS vulnerability management: https://www.sans.org/blog/vulnerability-management/  
- MITRE ATT&CK for mapping findings to behaviors: https://attack.mitre.org/

### Portfolio tip
- **Add this:** “Led authenticated/unauthenticated vuln scans; validated findings; produced remediation plan.”

---

## Week 7: Security operations

### Objectives
- **Centralize logs:** Configure rsyslog shipping to Kali.
- **Build a mini-SIEM view:** Parse logs and create basic alerts.
- **Triage a simulated incident:** Failed SSH brute-force with Fail2ban response.

### Prerequisites
- **Debian:**  
  ```
  sudo apt install rsyslog
  ```
- **Kali:**  
  ```
  sudo apt install rsyslog logrotate jq
  ```

### Core exercises
- **Exercise 1 — Rsyslog forwarding (Debian → Kali)**
  - **Scenario:** Ship auth/system logs to Kali for analysis.
  - **Commands (Debian):**  
    ```
    sudo nano /etc/rsyslog.conf
    # *.* @@<KALI_IP>:514
    sudo systemctl restart rsyslog
    ```
    (Kali):  
    ```
    sudo nano /etc/rsyslog.conf
    # module(load="imudp") input(type="imudp" port="514")
    # module(load="imtcp") input(type="imtcp" port="514")
    sudo systemctl restart rsyslog
    sudo tail -f /var/log/syslog
    ```
  - **Debrief:** Confirm inbound logs; segregate by hostname.

- **Exercise 2 — Parse and alert**
  - **Scenario:** Detect >5 failed SSH attempts within 10 minutes.
  - **Tools used:** jq/grep/cron script.
  - **Commands (Kali):**  
    ```
    sudo grep "Failed password" /var/log/syslog | awk '{print $1,$2,$3,$NF}' > failed_ssh.txt
    ```
    Create a simple script to count failures and echo “ALERT” when threshold exceeded; schedule via cron.
  - **Debrief:** Show alert output and correlate with Fail2ban actions.

- **Exercise 3 — Incident triage runbook**
  - **Scenario:** Document steps for detection, containment, eradication, recovery.
  - **Tools used:** Markdown runbook.
  - **Steps:** Include log sources, queries, escalation paths, and evidence checklist.

### Assessment
- **Runbook + evidence:** Screenshot of forwarded logs, alert script output, Fail2ban status.
- **Quiz:**  
  - **Q1:** What log fields are most useful for SSH brute-force detection?  
  - **Q2:** Why centralize logs?  
  - **Q3:** What’s the first containment step in your runbook?

### Resources
- NIST SP 800-61 (incident handling): https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final  
- CISA logging guidance: https://www.cisa.gov/resources-tools/resources/logging-made-easy  
- MITRE ATT&CK (initial access/brute force): https://attack.mitre.org/techniques/T1110/

### Portfolio tip
- **Add this:** “Built mini-SIEM with rsyslog; created alert for SSH brute-force; authored incident triage runbook.”

---

## Week 8: Cloud security (local-friendly simulation)

### Objectives
- **Understand cloud-like controls:** Use Docker to simulate services and apply security configs.
- **Scan container images/services:** Assess vulnerabilities.
- **Document shared responsibility model (lab context).**

### Prerequisites
- **Kali or Debian (choose host):**  
  ```
  sudo apt install docker.io docker-compose
  sudo systemctl enable --now docker
  ```
- **Kali:**  
  ```
  sudo apt install trivy
  ```

### Core exercises
- **Exercise 1 — Deploy a simple container**
  - **Scenario:** Run an Nginx container and secure it.
  - **Commands:**  
    ```
    sudo docker run -d --name lab-nginx -p 8080:80 nginx:alpine
    sudo docker exec -it lab-nginx sh -c 'nginx -v'
    ```
  - **Debrief:** Map exposed port and config to cloud-like ingress/egress controls.

- **Exercise 2 — Image scanning with Trivy (Kali)**
  - **Scenario:** Identify vulnerabilities in container images.
  - **Commands:**  
    ```
    trivy image nginx:alpine > trivy_nginx.txt
    ```
  - **Debrief:** Note CVEs, severities, and remediation paths (update/tag pinning).

- **Exercise 3 — Secure container runtime**
  - **Scenario:** Apply minimal privileges and logging.
  - **Commands:**  
    ```
    sudo docker run -d --name lab-nginx-secure \
      --read-only --cap-drop=ALL -p 8081:80 nginx:alpine
    ```
  - **Debrief:** Explain principle of least privilege in containers; capture access logs.

### Assessment
- **Mini report:** Shared responsibility (you vs. platform), scan results, hardened deployment evidence.
- **Quiz:**  
  - **Q1:** What’s the shared responsibility model?  
  - **Q2:** Why scan images regularly?  
  - **Q3:** How do runtime flags reduce attack surface?

### Resources
- NIST SP 800-190 (container security): https://csrc.nist.gov/publications/detail/sp/800-190/final  
- CIS Docker benchmark: https://www.cisecurity.org/benchmarks  
- CISA cloud security guidance: https://www.cisa.gov/resources-tools/resources/cloud-security

### Portfolio tip
- **Add this:** “Simulated cloud controls with Docker; scanned and hardened containers per CIS/NIST guidance.”

---

## Week 9: Governance integration (policy + audit)

### Objectives
- **Draft core policies:** Acceptable Use, Access Control, Logging/Monitoring.
- **Audit for compliance:** Check lab controls against your policies and standards.
- **Create executive summary:** Clear, non-technical reporting.

### Prerequisites
- **Tools:** Markdown editor, Lynis re-run.

### Core exercises
- **Exercise 1 — Policy drafting**
  - **Scenario:** Create 3 concise policies tailored to your lab.
  - **Tools used:** Policy templates (your own).
  - **Steps:** Define scope, roles, requirements, exceptions, enforcement, review cadence.

- **Exercise 2 — Audit against policies**
  - **Scenario:** Validate implementation (e.g., SSH MFA, logging, UFW).
  - **Commands:**  
    ```
    sudo lynis audit system | tee ~/lynis_week9.log
    sudo ufw status verbose
    sudo fail2ban-client status sshd
    grep -E "pam_google|Banner|ChallengeResponse" /etc/ssh/sshd_config
    ```
  - **Debrief:** Mark compliant/non-compliant; assign actions.

- **Exercise 3 — Executive summary**
  - **Scenario:** Write a one-page summary for leadership.
  - **Content:** Risks, mitigations, progress, top recommendations with timelines.

### Assessment
- **Deliverables:** 3 policies (Markdown), audit checklist, executive summary PDF.
- **Quiz:**  
  - **Q1:** Why separate policy from procedure?  
  - **Q2:** What evidence proves logging is centralized?  
  - **Q3:** Which control areas remain gaps?

### Resources
- ISO/IEC 27001 overview: https://www.iso.org/standard/27001  
- NIST policy guidance library: https://csrc.nist.gov/projects/risk-management  
- CISA governance best practices: https://www.cisa.gov/resources-tools/resources/cybersecurity-best-practices

### Portfolio tip
- **Add this:** “Authored lab policies; performed compliance audit; delivered executive-ready governance summary.”

---

## Week 10: Vulnerability testing (ethical pentest simulation)

### Objectives
- **Plan and execute a scoped test:** Write rules of engagement and test plan.
- **Use Metasploit safely:** Probe one service with non-destructive modules.
- **Report findings with remediation.**

### Prerequisites
- **Kali:**  
  ```
  sudo apt install metasploit-framework
  msfdb init
  ```
- **Debian:** Snapshot/backup key configs before testing.

### Core exercises
- **Exercise 1 — Rules of engagement**
  - **Scenario:** Formalize authorization and scope (your lab only).
  - **Content:** In-scope assets (Debian IP), time window, allowed techniques, stop conditions, logging requirements.

- **Exercise 2 — Recon and enumeration**
  - **Commands (Kali):**  
    ```
    nmap -sC -sV -oA week10_recon <DEBIAN_IP>
    ```
  - **Debrief:** Select one safe target (e.g., test TLS port or SSH) and find relevant Metasploit auxiliary modules.

- **Exercise 3 — Metasploit auxiliary testing**
  - **Tools used:** Metasploit (auxiliary scanners).
  - **Commands:**  
    ```
    msfconsole
    search ssh_version
    use auxiliary/scanner/ssh/ssh_version
    set RHOSTS <DEBIAN_IP>
    run
    ```
    For TLS:  
    ```
    use auxiliary/scanner/ssl/openssl_heartbleed
    set RHOSTS <DEBIAN_IP>
    set RPORT 4433
    run
    ```
  - **Debrief:** Use only safe, non-exploit scanners; record results; confirm no service instability.

### Assessment
- **Pentest-lite report:** Scope, ROE, recon results, module outputs, risk ratings, remediation steps, evidence.
- **Quiz:**  
  - **Q1:** Why document ROE before testing?  
  - **Q2:** What distinguishes auxiliary scanners from exploits?  
  - **Q3:** How do you verify no adverse impact?

### Resources
- OWASP testing methodology: https://owasp.org/www-project-web-security-testing-guide/  
- SANS pentest tips: https://www.sans.org/blog/pentesting-tips/  
- MITRE ATT&CK mapping to tactics/techniques: https://attack.mitre.org/

### Portfolio tip
- **Add this:** “Executed ethical, scoped vulnerability test using Metasploit auxiliary modules; delivered remediation report.”

---

## Progression notes

- **Build-up:** Risk assessment (Week 1) informs which assets (Week 2) to harden (Week 3), then verify via traffic analysis (Week 4) and IAM controls (Week 5). Scans (Week 6) validate hardening; operations (Week 7) detect and respond. Cloud simulation (Week 8) broadens scope. Governance (Week 9) ties it all together. Final testing (Week 10) demonstrates safe offensive awareness supporting defensive posture.
- **Ethics reminder:** Operate only within your lab; document authorization; follow responsible disclosure principles (even in simulations).

---

## Ongoing portfolio and resume guidance

- **Evidence pack:** Keep terminal outputs, config diffs, pcap screenshots, and Markdown reports in a GitHub repo (redact any PII or secrets).
- **Quantify impact:** Note metrics such as “reduced exposed services from 6 to 2,” “blocked 100% of simulated brute-force attempts,” “raised Lynis score by X.”
- **Role alignment:** Emphasize SOC-relevant outcomes: detection rules, triage runbooks, vulnerability remediation plans, and governance artifacts.