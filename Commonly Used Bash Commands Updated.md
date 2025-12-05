Commonly Used Commands Updated
#### Step 1: Identify Most Common Commands
From the previous analysis, the top commands across both histories (Ubuntu: 543 commands, Kali: 420 commands) are:
- `sudo` (559 uses)
- `apt` (190 uses)
- `systemctl` (84 uses)
- `nano` (56 uses)
- `ssh` (64 uses)

I'll also include other frequently used commands relevant to your lab activities (`lynis`, `ufw`, `nmap`, `hydra`, `curl`) to provide a comprehensive overview, focusing on their cybersecurity applications.

#### Step 2: Redact PII
The logs contain PII such as:
- Usernames: `kevin`, `kcurtis`, `analyst`
- IP addresses: `192.168.0.102`, `192.168.1.183`, etc.
- Passwords: `1G0d4Giveus`, `22Ion3224$`, etc.
- SSH keys: `ssh-ed25519 AAAAC3NzaC...`
- Hostnames: `labserver`, `kevin-HP-Laptop-17-by1xxx`

These will be replaced with placeholders (e.g., `[USER]`, `[IP_ADDRESS]`, `[PASSWORD]`, `[SSH_KEY]`) or omitted where appropriate.

#### Step 3: Structure the Markdown File
The file will include:
- A header with context about your lab and its relevance to your certifications (ISC² CC, Google Cybersecurity Professional).
- A table listing each command, its frequency, purpose, example (redacted), and cybersecurity use case.
- Notes on how these commands support your ethical hacking and system hardening efforts.
- A footer encouraging contributions and linking to CIS benchmarks for further reading.

---

### Markdown File Content

```markdown
# Common Linux Commands in Cybersecurity Lab

This document summarizes the most frequently used commands in my home cybersecurity lab, built to support my transition into cybersecurity with certifications like ISC² CC and Google Cybersecurity Professional. The lab includes a hardened Ubuntu server and a Kali Linux workstation for ethical hacking practice, aligned with TryHackMe and CompTIA Security+ prep. Commands are drawn from command histories, with sensitive information (usernames, IPs, passwords, keys) redacted for privacy.

## Overview

The commands below reflect system administration, security hardening, and penetration testing activities. They are organized by frequency and include explanations of their purpose and cybersecurity applications. This file is part of my GitHub repository to document progress and share knowledge.

## Common Commands

| Command     | Frequency | Purpose                              | Example (Redacted)                              | Cybersecurity Use Case                     |
|-------------|-----------|--------------------------------------|------------------------------------------------|-------------------------------------------|
| `sudo`      | 559       | Execute commands with root privileges | `sudo apt update`                              | Elevate privileges for admin tasks (e.g., installing security tools). Monitor for unauthorized use. |
| `apt`       | 190       | Manage packages on Debian/Ubuntu      | `sudo apt install lynis -y`                    | Install/update security tools (e.g., `lynis`, `fail2ban`). Ensure only trusted packages are installed. |
| `systemctl` | 84        | Manage system services               | `sudo systemctl restart ssh`                   | Start/stop services like SSH or SIEM (e.g., Elasticsearch). Detect disabled security services. |
| `nano`      | 56        | Edit text files                      | `sudo nano /etc/ssh/sshd_config`               | Modify configs for hardening (e.g., SSH, UFW). Audit changes to critical files. |
| `ssh`       | 64        | Secure remote access                 | `ssh [USER]@[IP_ADDRESS] -p 2222`              | Access lab servers for testing. Enforce MFA and monitor for unauthorized access. |
| `lynis`     | 30        | System security auditing             | `sudo lynis audit system`                      | Identify vulnerabilities and hardening gaps. Regular audits improve security posture. |
| `ufw`       | 29        | Manage firewall rules                | `sudo ufw allow 2222/tcp`                      | Restrict network access to secure services. Verify rules to prevent open ports. |
| `nmap`      | 18        | Network scanning                     | `nmap -sS [IP_ADDRESS]`                        | Reconnaissance for ethical hacking. Unauthorized scans indicate potential attacks. |
| `curl`      | 16        | Transfer data via HTTP/HTTPS          | `curl -I http://[IP_ADDRESS]`                  | Test web services or APIs. Monitor for data exfiltration attempts. |
| `hydra`     | 6         | Password brute-forcing               | `hydra -l [USER] -P wordlist.txt ssh://[IP_ADDRESS]:2222` | Test credential strength in lab. Detect brute-force attacks with Fail2Ban. |

## Explanations and Context

- **System Administration**: Commands like `sudo`, `apt`, and `systemctl` are essential for maintaining and securing Linux systems. In my lab, I use them to install tools (e.g., `lynis`, `fail2ban`), manage services (e.g., SSH, Elasticsearch), and update systems to patch vulnerabilities.
- **Security Hardening**: `lynis`, `ufw`, and `nano` (for editing configs like `/etc/ssh/sshd_config`) help harden the Ubuntu server. For example, I configured SSH to use port 2222, disabled root login, and enforced key-based authentication.
- **Penetration Testing**: On Kali, `nmap`, `hydra`, and `curl` support ethical hacking exercises, such as scanning ports or testing SSH credentials. These align with TryHackMe rooms and prepare for CompTIA Security+.
- **Monitoring and Auditing**: Tools like `lynis` and `systemctl` (for checking service status) enable proactive security monitoring, a key skill for ISC² CC and Google Cybersecurity certs.

## Notes

These commands are typical in a cybersecurity lab but may raise red flags in a production environment if unauthorized. For example:
- `nmap` or `hydra` could indicate an attacker probing the network.
- Unauthorized `apt` installs or `systemctl` commands stopping services may suggest compromise.

To detect such activities, I’m implementing:
- **Auditd**: Logs command execution (e.g., `auditctl -w /bin/bash -p x -k user_commands`).
- **Fail2Ban**: Blocks brute-force SSH attempts.
- **Elasticsearch/Kibana**: Analyzes logs for anomalies (e.g., frequent `nmap` usage).

## Contributing

Feel free to suggest additional commands or use cases via GitHub issues or pull requests. This repo is a living document of my cybersecurity journey.

## Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) for Linux hardening.
- [TryHackMe](https://tryhackme.com/) for hands-on labs.
- [Ubuntu Security Guide](https://ubuntu.com/security) for server best practices.

---
Generated on December 05, 2025
```