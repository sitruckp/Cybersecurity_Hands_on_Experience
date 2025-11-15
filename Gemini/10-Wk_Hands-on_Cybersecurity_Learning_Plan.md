10-Week Hands-on Cybersecurity Analyst Learning Plan

Week 1: Security and Risk Management 🛡️

Domain Focus: Risk assessments, compliance basics (NIST Risk Management Framework).

Objectives

    Asset Categorization (CIA Triad): Categorize the Debian server's impact level (Confidentiality, Integrity, Availability).

    Threat/Vulnerability Identification: Map observed vulnerabilities (like open ports) to threat actor tactics using MITRE ATT&CK.

    Control Gap Analysis: Identify missing security controls (e.g., encryption) based on the target system's security category.

Prerequisites

No new tools are needed this week. We are using built-in system commands and documentation tools.

Core Exercises

Lab 1: Asset Impact Categorization (CIA Triad)

    Scenario: Define the security requirements for the Debian server, which holds custom configuration files and access keys.

    Tool: CIA Triad (Confidentiality, Integrity, Availability).

        What it is: A fundamental model for classifying data/systems based on their security needs.

        What it does: Determines the impact level (Low, Moderate, High) of a breach.

        Why Relevant: Dictates the necessary security controls, aligning with the NIST Risk Management Framework Categorize step.

    Commands (Documentation on Host PC):

        Integrity Impact Assessment: Modification of system configuration files (e.g., UFW rules) is considered a High impact as it compromises server trust.

    Debrief: Your highest impact level (Integrity: High) sets the overall security category to High. This means we must apply strong, corresponding controls (like encryption) to protect it.

Lab 2: Initial Vulnerability & Threat Identification

    Scenario: Use built-in tools to review the current attack surface and map potential threats.

    Tool: ss -tuln and MITRE ATT&CK Framework.

        What it is: ss is a command to inspect network sockets.

        What it does: Shows all actively listening ports and their associated IP addresses, helping identify the attack surface.

        Why Relevant: Directly identifies open services an attacker could target, informing the Threat Assessment phase.

    Commands (On Debian Server):
    Bash

    # Check for actively listening ports (Network Security)
    sudo ss -tuln

        Output Explanation: The output shows TCP listening on Port 2222 (0.0.0.0:2222) for SSH.

    Debrief: The open SSH port is a vulnerability. The corresponding threat tactic is T1078 (Valid Accounts), which covers brute-force attacks against that service. Your SSH key-based authentication acts as a control to lower the likelihood of this risk.

Lab 3: Control Mapping and Residual Risk Calculation

    Scenario: Formally map your existing controls to compliance standards and document control gaps.

    Tool: NIST SP 800-53 Control Families (e.g., AC: Access Control, CM: Configuration Management).

        What it is: A catalogue of security controls for federal systems.

        What it does: Provides an auditable structure for defining, implementing, and assessing security requirements.

        Why Relevant: SOC Analysts use these controls (or similar frameworks like ISO 27001/CIS) daily for documentation and audit support.

    Commands/Steps (Documentation on Host PC):

        Map Control: SSH Key-Based Auth → NIST AC-3 (Access Enforcement).

        Gap Identification: Observe that sensitive files (like configuration files) are currently stored unencrypted on the disk.

        Document Residual Risk: The lack of data-at-rest encryption (NIST SC-28 control gap) results in a High Residual Risk (R-002).

    Debrief: We have established a top priority: addressing the high residual risk of unencrypted data. This flows directly into Week 2.

Assessment

Submit the completed Top 3 Identified Risks table (Markdown format) as demonstrated previously.

Resources

    NIST Risk Management Framework (RMF) Overview: NIST RMF Page

    MITRE ATT&CK Website: MITRE ATT&CK (Focus on the Linux platform).

    PDF Tie-in: Review Page 32 of infosec-best-practices.pdf for the importance of NIST and ISO certifications.

Progression

Week 2 will execute the mitigation plan for the high residual risk R-002 (unencrypted data) identified this week.

Portfolio Builder Tip

    "Conducted an initial NIST Risk Management Framework (RMF) assessment on a hardened Debian server, establishing a High Integrity security category and documenting key residual risks based on the MITRE ATT&CK framework."

Week 2: Asset Security 💾

Domain Focus: Inventory/classify assets, implement data protection (mitigating R-002).

Objectives

    Asset Inventory: Catalog critical system files, services, and local users on the Debian server.

    Data at Rest Protection: Implement data-at-rest encryption for sensitive configuration data using a file-level tool (mitigating R-002).

    Baselines: Document the current server configuration as a security baseline for future change control (CM-3).

Prerequisites

We will install GnuPG (GPG), a command-line tool for encryption, which is often used by analysts for protecting sensitive notes or configuration backups.

On Debian Server:
Bash

sudo apt update
sudo apt install gnupg -y

Core Exercises

Lab 1: Comprehensive Asset Inventory

    Scenario: Before securing the asset, you must know everything running on it.

    Tool: dpkg (Debian package manager), find (file locator).

        What it is: dpkg tracks all installed software packages.

        What it does: Helps the analyst create a software inventory list, which is crucial for patch management (NIST SI-2).

        Why Relevant: Every piece of installed software is a potential vulnerability.

    Commands (On Debian Server):

        Create Software Inventory List:
        Bash

dpkg --get-selections > ~/asset_inventory_software.txt

Identify Sensitive Files (Example):
Bash

        # Locate all files ending in .conf in the /etc directory
        sudo find /etc -name "*.conf" > ~/asset_inventory_configs.txt

    Debrief: The inventory list (asset_inventory_software.txt) now serves as your Configuration Baseline (NIST CM-3). Any unauthorized package installation in the future will be a violation of this baseline, which SOC Analysts monitor.

Lab 2: Implement Data-at-Rest Encryption (GPG)

    Scenario: Encrypt your sensitive asset inventory files to mitigate the High Residual Risk (R-002).

    Tool: GnuPG (GPG).

        What it is: A utility implementing the OpenPGP standard for public-key cryptography.

        What it does: Allows you to encrypt files using a passphrase or key, protecting data from unauthorized access even if the system is breached.

        Why Relevant: Satisfies the NIST SC-28 (Protection of Information at Rest) control, a key part of protecting Confidentiality.

    Commands (On Debian Server):

        Encrypt the Sensitive File (use a strong passphrase):
        Bash

gpg -c ~/asset_inventory_configs.txt

    Output Explanation: The file asset_inventory_configs.txt.gpg is created. The original file remains until you manually delete it.

Verify Encryption (Attempt to read the encrypted file):
Bash

cat ~/asset_inventory_configs.txt.gpg
# Expected Output: Unreadable, garbled binary data.

Decrypt the file (Test Access):
Bash

        gpg -o decrypted_configs.txt -d ~/asset_inventory_configs.txt.gpg
        # Prompts for passphrase, then outputs the clean file.

    Debrief: You have successfully reduced the impact of R-002. If an attacker gains access to the non-root user account, the sensitive inventory data is protected by encryption. This directly links to the Data Security principles in your Google Cybersecurity Certificate.

Lab 3: System Hardening Baseline Verification

    Scenario: Verify existing hardening controls like the non-root user and UFW status against the baseline audit.

    Tool: whoami and sudo ufw status verbose.

        What it is: These are auditing commands.

        What it does: Verifies that your core configurations (non-root access, firewall rules) are active and correct.

        Why Relevant: SOC Analysts constantly verify security controls against their documented baseline to ensure operational effectiveness.

    Commands (On Debian Server):
    Bash

    # Verify non-root user (Principle of Least Privilege)
    whoami

    # Verify firewall is active (Network Defense)
    sudo ufw status verbose

    Debrief: Document the output of ufw status to confirm that the firewall is active and only allows incoming traffic on port 2222 (your custom SSH port). This solidifies your current defense posture before we look at architecture.

Assessment

Mini-Report: Document your GPG implementation (passphrase chosen, file size difference, verification steps) and conclude whether Risk R-002 has been mitigated from High to Low/Medium.

Resources

    GPG Command Line Tutorial: GnuPG Mini Howto

    CIS Controls 1 & 3 (Inventory): CIS Controls v8 - Review Control 1 (Inventory and Control of Enterprise Assets).

    PDF Tie-in: Reference Page 3 of infosec-best-practices.pdf which highlights the need for secure handling of sensitive data.

Progression

Week 3 will build upon this by organizing all implemented controls into a layered Defense-in-Depth architecture.

Portfolio Builder Tip

    "Implemented and validated NIST SC-28 (Protection of Information at Rest) by deploying GPG file-level encryption on critical configuration files, successfully mitigating a documented High Residual Risk to an acceptable level."

Week 3: Security Architecture and Engineering 🏗️

Domain Focus: Design layered defenses, apply defense-in-depth, configure UFW segmentation.

Objectives

    Defense-in-Depth Design: Conceptualize and diagram the server's security controls in layers (e.g., Perimeter, Network, Host, Data).

    Firewall Segmentation: Configure the UFW firewall to strictly enforce the Principle of Least Functionality by restricting outgoing network access for most services.

    System Hardening: Apply a kernel hardening technique via sysctl to defend against common network attacks (e.g., SYN flooding).

Prerequisites

No new tools are needed this week. We are using the pre-installed UFW and sysctl.

Core Exercises

Lab 1: Defense-in-Depth (DiD) Conceptual Diagram

    Scenario: Architecturally review your current server setup and organize its controls into logical layers.

    Tool: Defense-in-Depth (DiD) model.

        What it is: A strategy that employs multiple, layered security controls to protect assets. If one layer fails, another is there to back it up.

        What it does: Moves beyond a single point of failure (like a perimeter firewall).

        Why Relevant: A core concept for SOC Analysts; knowing the layers helps prioritize which alert is most critical.

    Commands/Steps (Documentation on Host PC):

        Draft DiD Layers:

            Perimeter: Your Router/ISP Firewall (External Defense).

            Network: UFW Firewall (Host-level Segmentation).

            Host: Kernel Hardening (System-level defense), SSH Key Auth (Access Control).

            Data: GPG Encryption (Data-at-Rest protection, from Week 2).

        Visualization: Sketch a simple layered diagram of the Debian server's defenses.

    Debrief: This exercise links your isolated commands to a professional security strategy. You can now articulate why you set up SSH keys and a firewall—they are two separate, redundant layers protecting the same service.

Lab 2: Enforcing Least Functionality with UFW

    Scenario: By default, your server can connect anywhere. Restrict its ability to make outgoing connections to minimize the impact of a potential compromise (e.g., preventing a malware beacon).

    Tool: UFW (Uncomplicated Firewall).

        What it is: A user-friendly front-end for the Linux netfilter firewall.

        What it does: Allows you to define strict rules for network traffic, both incoming and outgoing (NIST SC-7).

        Why Relevant: Enforces network segmentation, making it harder for an attacker who gains access to perform C2 (Command and Control) communication (MITRE ATT&CK T1071).

    Commands (On Debian Server):

        Set Default Outgoing Policy to Deny:
        Bash

sudo ufw default deny outgoing

Allow Necessary Outgoing Traffic (DNS and HTTP/HTTPS for updates/analysis):
Bash

# Allow DNS resolution (required for apt updates)
sudo ufw allow out to any port 53
# Allow HTTP/HTTPS (required for updates and future SIEM data forwarding)
sudo ufw allow out to any port 80,443 proto tcp

Review New Rules:
Bash

        sudo ufw status verbose

    Debrief: Test the change: can you still browse a website using curl? Can you now stop the SSH service, and can you still ping Google (if UFW allows ping)? These rules significantly improve your server's security posture by reducing the blast radius of a successful compromise.

Lab 3: Kernel Hardening against Network Flooding

    Scenario: Prevent Denial-of-Service (DoS) attacks, specifically a SYN flood, by adjusting kernel settings.

    Tool: sysctl.

        What it is: A utility to modify kernel parameters at runtime.

        What it does: Adjusts low-level system settings, including networking and memory management.

        Why Relevant: This is part of the Host Defense layer, protecting the system's availability (A in the CIA Triad).

    Commands (On Debian Server):

        Enable SYN cookie protection (against SYN floods):
        Bash

echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf

Apply the change without rebooting:
Bash

sudo sysctl -p

Verify the change:
Bash

        sudo sysctl net.ipv4.tcp_syncookies
        # Expected Output: net.ipv4.tcp_syncookies = 1

    Debrief: You have implemented a specific control (SC-5: Denial-of-Service Protection) mandated by standards like NIST. Kernel hardening is a key part of maintaining a strong security posture.

Assessment

Self-Check Quiz:

    What is the purpose of setting net.ipv4.tcp_syncookies = 1?

    If your UFW outgoing policy is set to deny, what MITRE ATT&CK tactic are you making harder for an attacker to achieve? (Hint: Think about external communication).

    Name one control you implemented in Week 2 (e.g., GPG) and which architectural layer it belongs to.

Resources

    Defense in Depth Tutorial: SANS Technology Institute

    Linux Networking Hardening: CIS Debian Linux Benchmark (Review section 3.2 on Network Parameter Settings).

    PDF Tie-in: Reference the Defense-in-Depth concept mentioned on Page 5 of infosec-best-practices.pdf.

Progression

Week 4 focuses on testing the Network and Communication layer we just configured by actively analyzing the traffic that UFW allows through.

Portfolio Builder Tip

    "Engineered and implemented a Defense-in-Depth (DiD) security architecture on a lab server, enforcing the Principle of Least Functionality through outbound UFW network segmentation (blocking C2 traffic) and implementing kernel-level SYN flood protection."

Week 4: Communication and Network Security 🌐

Domain Focus: Secure protocols, traffic inspection, packet analysis.

Objectives

    Protocol Analysis: Capture and analyze SSH traffic to understand the characteristics of a secure protocol handshake.

    Vulnerability Identification: Identify clear-text or insecure protocols (if any are accidentally running) on the network segment using sniffing tools.

    Filtering & Triage: Practice using Wireshark display filters to isolate relevant data, mimicking a SOC triage task.

Prerequisites

You will need to install Wireshark on your Kali Linux machine.

On Kali Linux:
Bash

sudo apt update
# Wireshark is often pre-installed, but this ensures it is ready
sudo apt install wireshark -y
# Add your user to the wireshark group (important!)
sudo usermod -aG wireshark $USER
echo "You must log out and log back in for the Wireshark group change to take effect!"

Core Exercises

Lab 1: Baseline SSH Traffic Capture

    Scenario: You need to confirm that your SSH connection (Port 2222) is using modern, secure encryption protocols.

    Tool: Wireshark (on Kali) and SSH (on Kali/Debian).

        What it is: The world's most widely used network protocol analyzer.

        What it does: Captures network packets in real-time and allows deep inspection of their contents.

        Why Relevant: A foundational SOC skill. Analysts use packet captures (PCAPs) to confirm suspicious activity or rule out false positives.

    Commands (Steps):

        Start Wireshark (on Kali): Open Wireshark as your regular user (after logging in again). Select your network interface (e.g., eth0 or wlan0) and start capture.

        Generate Traffic (on Kali): Open a second terminal and SSH into your Debian server:
        Bash

        ssh kevin@<Debian_IP_Address> -p 2222

        Perform Action (on Debian): Run a few simple commands like ls -l and cat /etc/os-release.

        Stop Capture: Close the SSH connection and stop the capture in Wireshark.

    Debrief: Look at the packets. You should see a handshake followed by a long stream of data labeled as Encrypted Data. You should not see the actual commands (ls -l, etc.) in the packet contents. This confirms the use of a secure protocol (SC-8).

Lab 2: Triage with Display Filters

    Scenario: Your security team detects high traffic volume on the network. You must quickly isolate all traffic related to your Debian server's SSH service.

    Tool: Wireshark Display Filters.

        What it is: A powerful feature in Wireshark to selectively show only the packets that match a defined criteria.

        What it does: Filters out noise, allowing the analyst to focus on the key communication packets.

        Why Relevant: Essential for incident response triage, where time is critical.

    Commands (In Wireshark Filter Bar):

        Filter by SSH Port: Type tcp.port == 2222 and press Enter. This isolates all traffic to and from the custom SSH port.

        Filter by IP Address: Try filtering only traffic from your Debian server: ip.src == <Debian_IP_Address>.

    Debrief: Practice combining filters (e.g., (tcp.port == 2222) && (ip.src == 192.168.0.102)). You are now performing a basic Traffic Analysis (DE.CM-4) function from the NIST Cybersecurity Framework.

Lab 3: Insecure Protocol Simulation (Optional)

    Scenario: To fully appreciate secure protocols, simulate the use of an insecure one.

    Tool: Telnet. (This is for educational purposes only, as Telnet is highly insecure and should never be used on a real network).

    Commands (On Debian Server): Temporarily install Telnet server for this isolated lab only:
    Bash

sudo apt install telnetd -y

On Kali (Attacker/Analyst):

    Start a new Wireshark capture.

    Connect to the Debian server:
    Bash

        telnet <Debian_IP_Address>

        Log in and type a command. Stop the capture.

    Debrief: CRITICAL: Use a Wireshark filter of telnet. The data packets will show your credentials and commands in clear-text. This is the fundamental security failure that protocols like SSH (and the use of encryption from infosec-best-practices.pdf) were designed to solve. Immediately uninstall Telnet server on Debian: sudo apt remove telnetd --purge -y.

Assessment

Mini-Report:

    Screenshot your Wireshark PCAP showing the difference between Telnet (clear-text) and SSH (encrypted data).

    Explain why Telnet poses an extreme security risk (Confidentiality failure).

Resources

    Wireshark Video Tutorial (Filters): Search YouTube for "Wireshark Display Filters Tutorial" (focus on basic IP/Port filters).

    NIST SP 800-53 SC-8: NIST SP 800-53 Rev. 5 (Review the requirements for Transmission Integrity).

    PDF Tie-in: See Chapter 15 of gray-hat-hacking.pdf for discussions on network sniffing and interception.

Progression

Week 5 moves from network access controls to user access controls, focusing on the core concept of Least Privilege.

Portfolio Builder Tip

    "Utilized Wireshark for hands-on network traffic analysis, confirming compliance with NIST SC-8 (Transmission Integrity) by validating the secure encryption handshake of the custom SSH service (Port 2222), and demonstrating the vulnerability of clear-text protocols like Telnet."

Week 5: Identity and Access Management 🔑

Domain Focus: Implement Role-Based Access Control (RBAC), Least Privilege, SSH Key Management.

Objectives

    Principle of Least Privilege (PoLP): Implement and audit sudoers rules to restrict the user's root access to only necessary commands.

    Key Management: Implement a formal process for creating, deploying, and revoking SSH keys (NIST AC-17).

    MFA Simulation: Simulate a Multifactor Authentication (MFA) requirement using an SSH tool (e.g., google-authenticator).

Prerequisites

We will install a PAM module to enable MFA simulation on your SSH service.

On Debian Server:
Bash

sudo apt update
# Install the Google Authenticator PAM module
sudo apt install libpam-google-authenticator -y

Core Exercises

Lab 1: Implementing Least Privilege via sudoers (RBAC)

    Scenario: Your user, kevin, needs root access only for managing UFW and system updates, not for general root shell access.

    Tool: visudo and the sudoers file.

        What it is: The configuration file that defines which users can run which commands as root (AC-3: Access Enforcement).

        What it does: Allows the system administrator to enforce Role-Based Access Control (RBAC) at the command level.

        Why Relevant: Enforcing PoLP is a primary SOC Analyst responsibility—it limits what an attacker can do after compromising a user account (MITRE ATT&CK T1548: Abuse Elevation Control Mechanism).

    Commands (On Debian Server):

        Open the sudoers file safely:
        Bash

sudo visudo

Add a specific, restrictive rule (Example): Add a line to the bottom, replacing the existing blanket rule for kevin:

kevin ALL=(ALL) /usr/sbin/ufw, /usr/bin/apt, /usr/bin/apt-get

Test the Restriction: Attempt to run a command that is not allowed (e.g., attempt to get a root shell).
Bash

        sudo /bin/bash
        # Expected Output: Command not allowed (unless you have a root login shell entry)

    Debrief: You have implemented a specific form of RBAC. This practice is detailed in the Access Management sections of infosec-best-practices.pdf.

Lab 2: SSH Key Management (AC-17)

    Scenario: You need a formal process for generating and deploying a new key for your Kali machine.

    Tool: ssh-keygen.

        What it is: A utility for creating key pairs (public and private).

        What it does: Provides a cryptographically strong, non-password way to authenticate, improving security over simple passwords.

        Why Relevant: Satisfies NIST control AC-17 (Remote Access) and is crucial for securing remote administration.

    Commands (On Kali Linux):

        Generate a new key (use a strong passphrase):
        Bash

ssh-keygen -t ed25519 -f ~/.ssh/debian_lab_key

Copy the Public Key to Debian:
Bash

        ssh-copy-id -i ~/.ssh/debian_lab_key.pub kevin@<Debian_IP_Address> -p 2222

    Debrief: You now have a formal, documented key pair. The private key must be protected (GPG encryption from Week 2 is a good idea!). Key rotation and destruction are critical parts of managing digital identities.

Lab 3: MFA Simulation via SSH

    Scenario: Add a second factor of authentication (a time-based one-time password or TOTP) to your SSH login.

    Tool: google-authenticator PAM module.

        What it is: A tool that generates the necessary configuration for a TOTP application (like Google Authenticator or Authy) to act as a second factor.

        What it does: Requires a code (something you have) in addition to your key/password (something you know), providing Multi-Factor Authentication (MFA).

        Why Relevant: MFA is a top CIS Control for preventing breaches (Reference Page 20 of Cybersecurity-best-practices-guide-2024-V2.pdf).

    Commands (On Debian Server):

        Run Setup and follow prompts (Answer Yes to updating .bashrc, No to rate limiting):
        Bash

google-authenticator

    Action: Scan the displayed QR code with your phone's TOTP app. Save the emergency codes!

Configure SSH to use the module (Edit two files):
Bash

        # Edit PAM configuration
        sudo nano /etc/pam.d/sshd
        # Add this line at the top (under the comment lines)
        # auth required pam_google_authenticator.so

        # Edit SSH server configuration
        sudo nano /etc/ssh/sshd_config
        # Change this line to 'yes'
        # ChallengeResponseAuthentication yes
        # Then restart SSH service
        sudo systemctl restart sshd.service

        Test Login (on Kali): Try SSHing in. You will now be prompted for the code from your app!

    Debrief: You have successfully implemented a form of MFA on a critical service. This is a massive improvement to your access control security.

Assessment

Self-Check Quiz:

    How does modifying the sudoers file enforce the Principle of Least Privilege?

    What NIST control family does SSH Key Management primarily fall under?

    Why is MFA considered more secure than key-based authentication alone (reference the three factors)?

Resources

    Secure SSH Configuration: CIS Controls 5 (Account Management).

    TOTP/MFA Explanation: CISA MFA Guide

    PDF Tie-in: Reference Page 20 of Cybersecurity-best-practices-guide-2024-V2.pdf for the critical importance of MFA.

Progression

Week 6 will switch back to the Kali machine to actively test the strength of the controls (SSH keys, UFW, MFA) we just implemented, simulating a threat actor's reconnaissance.

Portfolio Builder Tip

    "Enhanced server security by implementing Multi-Factor Authentication (MFA) on the custom SSH service (Port 2222) and enforcing Role-Based Access Control (RBAC) via sudoers, limiting the non-root user's root privileges to only essential maintenance commands."

Week 6: Security Assessment and Testing 🔎

Domain Focus: Vulnerability scanning, configuration assessment, vulnerability triage.

Objectives

    Vulnerability Scanning: Configure and run an authenticated, non-destructive vulnerability scan against the Debian server using OpenVAS/GVM.

    False Positive Triage: Analyze the scan results, identifying legitimate risks and triaging (disproving) common false positives.

    Mitigation Planning: Draft a plan to address the top 3 legitimate vulnerabilities discovered.

Prerequisites

You will need to install and set up the Greenbone Vulnerability Management (GVM) framework, which includes the OpenVAS scanner, on your Kali Linux machine. This process is resource-intensive and requires disk space.

On Kali Linux:
Bash

sudo apt update
# Install the GVM meta-package (includes OpenVAS)
sudo apt install gvm -y
# Run the setup script to finalize installation (this takes time!)
sudo gvm-setup
# Check the status
sudo gvm-check-setup

    Note: The setup script will provide the temporary admin password. Save it! You will access GVM via a web browser on Kali (usually at https://127.0.0.1:9392).

Core Exercises

Lab 1: Baseline Vulnerability Scan (Unauthenticated)

    Scenario: Run a baseline scan to see what an external, unauthenticated attacker can see.

    Tool: OpenVAS (Greenbone Vulnerability Management/GVM).

        What it is: A full-featured vulnerability scanner used by enterprises and penetration testers.

        What it does: Probes target systems for known security weaknesses, missing patches, and insecure configurations.

        Why Relevant: Simulates the reconnaissance phase (PCI DSS Requirement 11.3 and guidance in Penetration-Testing-Guidance-v1_1.pdf) and gives the analyst a prioritized list of issues.

    Steps (On Kali Linux):

        Log into the GVM Web Interface (e.g., https://127.0.0.1:9392).

        Navigate to Scans > Tasks. Create a New Task.

        Set the Target to your <Debian_IP_Address>.

        Select a "Full and Fast" scan configuration.

        Run the task.

    Debrief: The scan should mainly detect the open Port 2222 and maybe an old package. Your existing controls (UFW, kernel hardening) should block many simple checks.

Lab 2: Authenticated Scanning (Configuration Audit)

    Scenario: Now, run a privileged scan. This simulates a system administrator auditing the internal configuration of the server (a more thorough check).

    Tool: OpenVAS with SSH credentials.

        What it does: Logs into the target server using the provided credentials and runs internal configuration checks.

        Why Relevant: This is how you verify compliance with your own security policy (e.g., checking if the tcp_syncookies = 1 setting from Week 3 is actually active).

    Steps (On Kali Linux):

        In GVM, create a New Credential (Configuration > Credentials). Select SSH, and use the username and password (or private key) for your kevin user.

        Create a New Task, ensuring you select the new credential under the "User Credential" section.

        Run the task.

    Debrief: The authenticated scan will find far more issues, likely flagging configuration errors, old package versions, and non-compliance with the CIS Benchmark (like R-003, the locally bound PostgreSQL database).

Lab 3: Vulnerability Triage and Risk Rating

    Scenario: Analyze the results, distinguish between high-severity findings and acceptable risks.

    Tool: GVM Report Viewer and the CVSS score.

        What it is: The Common Vulnerability Scoring System (CVSS) provides a standard way to rate the severity of a vulnerability.

        What it does: Gives the SOC analyst a metric (Base Score) to prioritize remediation efforts.

        Why Relevant: Analysts use CVSS to triage alerts—a critical skill for incident response (IR).

    Steps (On Kali Linux):

        In the completed report, sort the findings by Severity (CVSS score).

        Triage a False Positive: You may see a high-severity alert for "Weak SSH Ciphers." Go into the finding details. If it lists ciphers you know you disabled (from your hardening steps), document it as a false positive.

        Triage a True Positive: Document the top real issue (e.g., an unpatched package) and its CVSS score.

    Debrief: This links to your certification's IR triage module. Prioritizing based on severity and confirming the finding is real (not a false positive) is the analyst's most important task.

Assessment

Mini-Report Template:

    Top Vulnerability Found (Name/CVE):

    CVSS Score:

    Impact on CIA Triad:

    Mitigation Recommendation: (e.g., Upgrade package-x to version y.z)

Resources

    OpenVAS/GVM Setup Guide: Greenbone Community Documentation

    CVSS Scoring Primer: FIRST CVSS Calculator

    PDF Tie-in: Review Page 4 of Penetration-Testing-Guidance-v1_1.pdf regarding the objective of penetration testing (which vulnerability scanning informs).

Progression

Week 7 will address one of the most common findings of any scan: logging. We will set up the system to send logs for centralized monitoring.

Portfolio Builder Tip

    "Conducted comprehensive Authenticated Vulnerability Scanning (NIST RA-5) using OpenVAS against a hardened Debian target. Identified and triaged 4 critical-severity findings, directly informing the creation of a prioritized patch management and remediation roadmap."

Week 7: Security Operations ⚙️

Domain Focus: Logging, monitoring, basic SIEM simulation, alert creation.

Objectives

    Centralized Logging: Configure the Debian server to forward its security logs to a remote location (simulating a SIEM) using rsyslog.

    Log Analysis: Manually examine logs for signs of the failed brute-force attacks we will simulate.

    SIEM Simulation: Use the Kali machine to receive logs and set up basic filters, mimicking a SOC Analyst's dashboard.

Prerequisites

We will configure rsyslog on Debian to send logs and configure netcat on Kali to act as a simple log receiver (simulating a SIEM).

On Debian Server (Sender):
Bash

# rsyslog is typically pre-installed
# We will configure it later in the lab.

On Kali Linux (Receiver/SIEM Sim):
Bash

sudo apt update
# Install netcat (nc) for listening
sudo apt install netcat -y

Core Exercises

Lab 1: Configuring Remote Log Forwarding (Log Shipping)

    Scenario: All security events must be sent to a central log collector for correlation and analysis (NIST AU-6: Audit Record Review, Analysis, and Reporting).

    Tool: rsyslog.

        What it is: A utility for collecting, processing, and forwarding system log messages.

        What it does: Ensures log data is sent off-device, protecting the audit trail from being tampered with if the host is compromised (critical for Integrity).

        Why Relevant: Log forwarding is the first step in setting up a SIEM (Security Information and Event Management) system, the main tool of a SOC Analyst.

    Commands (On Debian Server):

        Configure rsyslog to forward logs (Edit /etc/rsyslog.conf):
        Bash

sudo nano /etc/rsyslog.conf

Add this line at the bottom, replacing <Kali_IP_Address>:

# Send all logs (priority *) to the remote Kali machine on UDP 514
*.* @<Kali_IP_Address>:514

Restart the service:
Bash

        sudo systemctl restart rsyslog.service

    Debrief: We are using UDP 514 (the service you spotted with ss -tuln in Week 1). UDP is faster but unreliable; in a real environment, you'd use TCP for guaranteed delivery. This is the Implement step of the AU-6 control.

Lab 2: SIEM Simulation and Log Triage

    Scenario: The Kali machine needs to start listening for logs. Then, you will generate a log event (a failed login) and watch it appear in real-time.

    Tool: netcat (nc).

        What it is: A simple network utility known as a "TCP/IP Swiss Army knife."

        What it does: Allows the Kali machine to open a listener on UDP port 514 to receive the forwarded logs.

        Why Relevant: This mimics the log ingestion process of a full SIEM.

    Commands (Steps):

        Start Listener (On Kali Linux):
        Bash

        # Listen on UDP port 514
        sudo nc -ul 514

        Generate Event (On Debian Server): Open a new Debian terminal and intentionally fail the SSH login multiple times (try a few wrong passwords).

        Observe: Watch the Kali terminal. The failed login attempts will appear instantly.

    Debrief: The failed login messages are your first security events. The SOC Analyst's job is to create a rule (an Alert) for a pattern like "5 failed logins in 60 seconds." You just performed the Monitoring and Analysis part of NIST AU-6.

Lab 3: Security Alert Simulation (Triage & Response)

    Scenario: Filter the log stream to specifically detect a failed login attempt on SSH.

    Tool: grep (using a simple log file).

        What it is: A Linux utility for searching text using patterns (regular expressions).

        What it does: Analysts use grep in log files to quickly find specific strings, effectively creating manual alerts.

        Why Relevant: This is fundamental log analysis; every SIEM query is essentially a fancy grep (or regex) search.

    Commands (On Debian Server):

        View recent failed SSH attempts in the local log file:
        Bash

        # Search the authorization log for "Failed password"
        grep 'Failed password' /var/log/auth.log

        Log Triage: Identify the source IP address (your Kali machine) and the time stamp.

    Debrief: This exercise prepares you for Week 10's full simulation. You have successfully identified the indicators of compromise (IOCs) (failed logins) from the audit logs.

Assessment

Mini-Report: Create a Simulated Alert for a failed login:

    Alert Name: SSH Brute Force Attempt - Lab

    Source Host: lab-server

    Indicator of Compromise (IOC): Failed password for kevin from <Kali_IP>

    Triage Action: Investigate source IP, cross-reference with known threat intelligence, and notify manager if outside the lab network.

Resources

    Rsyslog Configuration Guide: rsyslog documentation

    Cyber Incident Log Analysis: SANS Whitepaper on Log Analysis

    PDF Tie-in: Review Page 10 of Cyber-Handbook-Enterprise.pdf regarding the role of SOC Analysts in threat monitoring.

Progression

Week 8 will introduce the concepts of cloud and hybrid environments by deploying a service in a local, cloud-like containerized environment.

Portfolio Builder Tip

    "Deployed and configured NIST AU-6 compliant log forwarding using rsyslog to ship system logs to a Kali-based SIEM simulator (netcat). Demonstrated ability to triage log data by identifying and analyzing simulated SSH brute-force attempts."

Week 8: Cloud Security ☁️

Domain Focus: Intro to hybrid environments, local Docker for cloud-like environments, configuration scanning.

Objectives

    Hybrid Simulation: Set up a containerized environment (Docker) on the Debian server to simulate a cloud-hosted web application (IaaS).

    Container Hardening: Scan the newly deployed container for misconfigurations using a local vulnerability scanner like Clair (or simply an authenticated OpenVAS scan from Week 6).

    Cloud Compliance: Identify the shared responsibility model's boundary for the simulated container service.

Prerequisites

You will need to install Docker on your Debian server to simulate a cloud platform (IaaS).

On Debian Server:
Bash

sudo apt update
# Install prerequisites
sudo apt install ca-certificates curl gnupg lsb-release -y
# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
# Add the repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
# Install Docker Engine
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io -y
# Add your user to the docker group (log out/in required)
sudo usermod -aG docker $USER
echo "You must log out and log back in for the Docker group change to take effect!"

Core Exercises

Lab 1: Deploying a Vulnerable Web Service (IaaS Simulation)

    Scenario: Deploy a simple Nginx web server in a container. This acts as a simulated AWS EC2 or Google Cloud VM hosting a service (IaaS).

    Tool: Docker.

        What it is: A platform for developing, shipping, and running applications in containers.

        What it does: Allows you to simulate a production environment (like a cloud VM) easily within your lab.

        Why Relevant: Cloud service security is a growing domain. Analysts need to understand the perimeter changes when moving from host-based security to a containerized/cloud environment.

    Commands (On Debian Server, after logging back in):

        Pull and Run an Nginx container (ports mapping):
        Bash

docker run --detach --publish 8080:80 --name my_web_service nginx
# --detach: runs in background
# --publish 8080:80: maps host port 8080 to container port 80

Verify the service is running:
Bash

        docker ps

    Debrief: You now have a web service exposed on port 8080. Since it's containerized, its vulnerabilities are separate from the Debian host's vulnerabilities. You've created a hybrid environment.

Lab 2: Scanning the Cloud Asset

    Scenario: Scan the new web service to identify common web application vulnerabilities and misconfigurations.

    Tool: Nmap (on Kali Linux) and OpenVAS (from Week 6).

        What it is: Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing.

        What it does: Identifies open ports, service versions, and OS information.

        Why Relevant: Nmap is the first tool an analyst or attacker uses to map out the cloud attack surface.

    Commands (On Kali Linux):

        Run an aggressive Nmap scan against the new service port:
        Bash

        nmap -sV -sC -p 8080 <Debian_IP_Address>

        Review Output: The output should confirm Port 8080 is open and running Nginx.

        Authenticated Scan (Conceptual): You would conceptually re-run the OpenVAS authenticated scan from Week 6, but this time, you would check for common image vulnerabilities (e.g., misconfigured environment variables in the container).

    Debrief: Nmap shows you the surface. The authenticated scan reveals the internal weaknesses. The goal is to see that the attack surface has expanded beyond just Port 2222.

Lab 3: Shared Responsibility Model (SRM) Analysis

    Scenario: Determine who (you or the cloud provider, simulated by the Nginx image creator) is responsible for patching the container's operating system.

    Tool: Shared Responsibility Model (SRM).

        What it is: A key cloud security concept defining the security tasks handled by the cloud provider and those handled by the customer.

        What it does: Provides the legal and operational boundary for security controls (NIST PR.IP-1).

        Why Relevant: SOC Analysts in cloud environments must know exactly where their responsibility for patching and hardening begins and ends.

    Analysis (Documentation on Host PC):

        Service Model: IaaS (Infrastructure as a Service) simulation.

        Cloud Provider (Nginx Image Creator) Responsibility: Security of the container runtime, physical security of the server.

        Customer (Your) Responsibility: Security in the container (e.g., application code, configuration hardening, and ensuring the Nginx service image is patched).

    Debrief: You realize that even in a basic IaaS model, you are still responsible for patching the Nginx image's underlying Linux OS—a critical concept for cloud compliance.

Assessment

Self-Check Quiz:

    What is the primary security benefit of using a container (like Docker) for a service?

    If the Nginx service (running in the container) is compromised, which security model (IaaS, PaaS, or SaaS) best describes the responsibility model where you must still patch the application code?

    Based on your Nmap scan, what new port has been added to the attack surface?

Resources

    Docker Security Best Practices: Docker Official Documentation

    AWS Shared Responsibility Model: AWS SRM Explanation (Use this as the conceptual reference).

    PDF Tie-in: Reference Page 34 of Cyber-Handbook-Enterprise.pdf which lists the Certified Cloud Security Engineer track, showing the career relevance of this domain.

Progression

Weeks 9 and 10 will integrate all knowledge. Week 9 will use the evidence gathered in Weeks 1-8 to build the compliance documentation (Governance).

Portfolio Builder Tip

    "Simulated a Hybrid Cloud IaaS environment using Docker, deploying and scanning an Nginx web service (Port 8080). Successfully mapped security boundaries using the Shared Responsibility Model to prioritize customer-side patching and configuration hardening efforts."

Week 9: Governance 📜

Domain Focus: Policy development, compliance auditing, policy enforcement.

Objectives

    Policy Drafting: Draft a simple Acceptable Use Policy (AUP) and Incident Notification Policy based on industry templates.

    Compliance Audit: Conduct a self-audit of the Debian server configuration against the CIS Benchmarks for key controls (e.g., SSH, password strength).

    Audit Reporting: Document a compliance report noting areas of weakness and non-compliance based on your findings from Weeks 1-8.

Prerequisites

No tools are needed this week, as the focus is on documentation and auditing the work done in previous weeks.

Core Exercises

Lab 1: Drafting the Acceptable Use Policy (AUP)

    Scenario: You need to create a simple policy that outlines how users (you) should and should not use the lab assets.

    Tool: Acceptable Use Policy (AUP) template.

        What it is: A policy that defines the acceptable activities for users of a system.

        What it does: Establishes a formal boundary for ethical and legal use (governance) and provides the basis for disciplinary action (e.g., if you install unapproved software).

        Why Relevant: Governance is the foundation of a security program. SOC Analysts use policies to justify their monitoring and enforcement actions.

    Steps (Documentation on Host PC):

        AUP Outline: Draft a short AUP with sections covering:

            Purpose: Define ethical, non-production use only.

            Prohibited Activities: No external scanning; no password sharing; no installation of unauthorized software.

            Acceptable Activities: Ethical testing, configuration hardening, personal learning.

        Incident Notification: Draft a procedure for what to do if you suspect the lab has been externally compromised (e.g., isolate the machine, notify yourself/a virtual manager).

    Debrief: The process of policy creation links the theory in your certifications to a tangible asset.

Lab 2: CIS Control Self-Audit

    Scenario: Use the hardening steps from Weeks 1-8 to assess your server's compliance against a recognized standard like the CIS Benchmark.

    Tool: CIS Benchmarks (Conceptually).

        What it is: Vendor-agnostic, consensus-driven security configuration guidelines.

        What it does: Provides a structured checklist for measuring the "hardened" status of a server.

        Why Relevant: Analysts frequently audit systems against CIS controls to determine the security posture (NIST CA-2: Control Assessments).

    Audit Steps (Review and Documentation):

        Review Control: CIS 5.1.1 (Ensure /etc/passwd is only group-writable by root). Check the file permissions:
        Bash

ls -l /etc/passwd
# Expected Output: -rw-r--r-- (owned by root, only root can write) - COMPLIANT

Review Control: CIS 5.3.1 (Ensure SSH Protocol is set to 2). Check your SSH config:
Bash

        grep 'Protocol' /etc/ssh/sshd_config
        # Expected Output: Protocol 2 - COMPLIANT

        Review Control: CIS 1.2.1 (Filesystem Separation). Did you separate user data? (Likely no). → NON-COMPLIANT.

    Debrief: The audit process reveals that even a "hardened" server has non-compliant areas. The job of Governance is to accept the risk of the non-compliant items or fund the remediation.

Lab 3: Security Program Scorecard

    Scenario: Document a final security posture scorecard synthesizing all your work.

    Tool: Compliance Scorecard/Report.

        What it is: A management-level summary of the security program's status.

        What it does: Translates technical findings into business risk for management.

        Why Relevant: This report is the core deliverable of any GRC (Governance, Risk, and Compliance) function.

    Steps (Documentation):

        Risk Mitigation Status: R-002 (Unencrypted Data) is Mitigated (GPG, Week 2).

        Access Control Status: Strong (RBAC via sudoers, MFA via PAM, Week 5).

        Top 1 Compliance Gap: CIS 1.2.1 Filesystem Separation.

    Debrief: You have now completed the entire NIST RMF cycle: Categorize (Week 1), Select/Implement (Weeks 2-5), Assess (Week 6), and Authorize/Monitor (Weeks 7 & 9).

Assessment

Mini-Report: Create the final Security Program Scorecard in a table format, showing the status (Compliant, Non-Compliant, Mitigated) for five key controls implemented over the last 8 weeks.

Resources

    CIS Control Examples: CIS Controls Quick Start (Review Controls 1-6).

    NIST SP 800-53 CA-2: NIST SP 800-53 Rev. 5 (Control for Control Assessments).

    PDF Tie-in: Use Page 5 of infosec-best-practices.pdf to justify the need for policy and access management controls in your report.

Progression

Week 10 is the ultimate test: a full-scope ethical hacking simulation to test the resilience of all your deployed controls.

Portfolio Builder Tip

    "Developed and executed a comprehensive CIS Benchmark compliance self-audit on the hardened lab server, successfully mapping technical controls (e.g., MFA, RBAC) to governance policy and generating a Security Program Scorecard for management."

Week 10: Vulnerability Testing 🔴

Domain Focus: Ethical pentesting, exploitation, post-exploitation, full red-team simulation.

Objectives

    Exploitation: Use Metasploit to attempt a basic, non-destructive attack against a service on the Debian server.

    Post-Exploitation Simulation: Simulate data collection and privilege escalation attempts on the Debian server.

    Final Incident Report: Document the entire red team simulation in a professional report format (similar to those mentioned in Penetration-Testing-Guidance-v1_1.pdf).

Prerequisites

We will ensure Metasploit is fully up to date on your Kali machine.

On Kali Linux:
Bash

sudo apt update
# Update Metasploit framework database
sudo msfdb init
# Start the Metasploit console
msfconsole

Core Exercises

Lab 1: Service Exploitation Attempt (Metasploit)

    Scenario: Attempt to exploit a known service. Since your server is well-hardened, we will focus on the local PostgreSQL database (R-003 risk) as a simulated target after gaining initial low-level access.

    Tool: Metasploit Framework (MSF).

        What it is: The world's most used open-source exploitation framework.

        What it does: Provides the tools, payloads, and exploits needed to test a system's vulnerability.

        Why Relevant: SOC Analysts need to understand how attacks work to effectively write detection rules and triage alerts. This links directly to the ethical hacking, student guide.pdf and gray-hat-hacking.pdf.

    Commands (On Kali Linux):

        Launch MSF: msfconsole

        Simulate an Internal Attack (PostgreSQL login attempt):
        Code snippet

        # Use an auxiliary module to attempt a login (non-destructive)
        use auxiliary/scanner/postgres/postgres_login
        set RHOSTS <Debian_IP_Address>
        set PASS_FILE /usr/share/wordlists/rockyou.txt
        set USERNAME postgres
        set STOP_ON_SUCCESS true
        run

    Debrief: Your hardening (non-default PostgreSQL settings, potential loopback binding) should cause the attack to fail. This is a success for the defense. The log from this attack (which you set up in Week 7) is a perfect detection signature.

Lab 2: Privilege Escalation (Post-Exploitation Simulation)

    Scenario: Assume the attacker gained access to the non-root user kevin. Now, they attempt to gain root access.

    Tool: Manual Check for Misconfigurations.

        What it is: Post-exploitation focuses on what an attacker does after gaining initial access (MITRE ATT&CK T1068: Exploitation for Privilege Escalation).

        What it does: Looks for configuration errors, weak file permissions, or unpatched kernel exploits to elevate privileges.

        Why Relevant: This tests the PoLP (Principle of Least Privilege) control from Week 5.

    Commands (On Debian Server, as kevin):

        Attempt sudo abuse (tests Week 5 RBAC):
        Bash

sudo /bin/bash
# Expected Result: Command not allowed (since you restricted sudoers) - Defense Hold

Check for SUID/SGID binaries (a common exploit vector):
Bash

        find / -perm -4000 2>/dev/null
        # Review the list for any non-standard binaries that could be exploited.

    Debrief: Your specific sudoers rules blocked the easy path to root, confirming the efficacy of your RBAC controls.

Lab 3: Final Professional Penetration Test Report

    Scenario: Consolidate all findings from the 10-week cycle into a final report.

    Tool: Penetration Test Report Template (Markdown).

        What it is: The professional deliverable of a security assessment.

        What it does: Summarizes the scope, findings, evidence, and remediation for a client (your virtual manager).

        Why Relevant: The report is the final stage of the Vulnerability Testing track (NIST CA-8: Penetration Testing).

    Report Sections (Minimum):

        Executive Summary: Hardening reduced the attack surface, MFA controls held.

        Scope & Objectives: Debian 13 server, custom SSH 2222, test controls.

        Findings (Top 3): R-002 mitigation confirmed (GPG), R-001 (SSH) controls held, CIS 1.2.1 Non-Compliance (Filesystem).

        Recommendations: Address CIS non-compliance.

    Debrief: You have now completed the entire cycle, from risk identification to defense implementation, to ethical testing, and final professional reporting. This is the full-spectrum skill set of an entry-level analyst.

Assessment

Final Incident Report: Submit the complete Penetration Test Report covering the last 10 weeks of work in professional Markdown format.

Resources

    Metasploit Console Basics: Rapid7 Metasploit Unleashed

    Privilege Escalation Techniques (Linux): HackTricks Linux PrivEsc

    PDF Tie-in: Reference the structure and purpose of testing as outlined in Page 4 of Penetration-Testing-Guidance-v1_1.pdf.

Portfolio Builder Tip

    "Led and executed a full-scope ethical Red Team simulation against a hardened lab asset, testing the resilience of MFA and RBAC controls, and producing a formal Penetration Test Report that documents 90% risk mitigation and outlines a final remediation plan."

This concludes your 10-week plan! After completing Week 10, share your final Incident Report. We can then discuss how to translate all these technical achievements into powerful resume content. Congratulations on completing this comprehensive program!