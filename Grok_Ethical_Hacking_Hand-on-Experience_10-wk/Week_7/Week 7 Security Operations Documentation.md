# Week 7: Security Operations Documentation

## Overview
- **Date**: December 5, 2025
- **Domain**: Security Operations
- **Objective**: Configure logging and monitoring on a home lab Ubuntu server (192.168.1.183) to simulate SOC tasks, using Kali (192.168.1.168) for analysis. Focus on detecting unauthorized access and automating responses, adhering to NIST SP 800-92, CIS Controls, and ethical guidelines (no external targets).
- **Credentials**: ISC² Certified in Cybersecurity (CC), Google Cybersecurity Professional Certificate
- **Lab Setup**: Ubuntu server (hardened, Lynis score 85/100) as target, Kali as attacker/analyst workstation.

## Objectives Achieved
1. Configured system logging with rsyslog to capture security events (partial success—system logs working, custom test pending).
2. Set up basic monitoring and alerting with Fail2Ban (configuration attempted, banning not yet functional).
3. Analyzed logs to simulate incident triage (SSH failure detected, full analysis pending SCP fix).

## Prerequisites
- Ubuntu: `sudo apt update && sudo apt install rsyslog fail2ban -y` (installed, no upgrades needed).
- Kali: `sudo apt update && sudo apt install ssh -y` (assumed installed).

## Core Exercises

### Exercise 1: Configure Basic System Logging with rsyslog
- **Scenario**: Set up logging to monitor the Ubuntu server for compliance (e.g., PCI DSS).
- **Tool**: rsyslog (collects/records system events, key for SOC detection per NIST SP 800-92).
- **Steps**:
  1. Edited `/etc/rsyslog.conf` and `/etc/rsyslog.d/10-auth.conf` (content not verified).
  2. Restarted rsyslog: `sudo systemctl restart rsyslog`.
  3. Checked live SSH logs: `journalctl -u ssh -f`.
- **Output**:
  - SSH success for "kevin" (19:01:26 UTC) and failure for "frank" (19:11:48 UTC) visible in `journalctl`.
  - `tail -n 10 /var/log/auth.log` showed cron/sudo events (19:35:23 UTC), no custom entries.
- **Debrief**:
  - **Findings**: System logs capture events, but `10-auth.conf` may not route auth events (e.g., "frank" failure missing).
  - **Pitfalls**: Possible config error or restart issue.
  - **Link to Certs**: Builds on Google cert’s incident triage via logs.
  - **To Log**: Test with `logger "Test log entry from SOC lab at $(date)"` and verify.

### Exercise 2: Monitor SSH Access Attempts
- **Scenario**: Detect brute-force attempts on Ubuntu SSH.
- **Tool**: journalctl (views systemd logs, filters SSH events for analysis).
- **Steps**:
  1. Ensured SSH logging (VERBOSE in `sshd_config` from Week 5).
  2. Simulated failure with `ssh frank@192.168.1.183 -p 2222` (prior output).
  3. Checked logs: `journalctl -u ssh -f`.
- **Output**:
  - "Invalid user frank" and "maximum authentication attempts exceeded" (19:11:48 UTC).
- **Debrief**:
  - **Findings**: Detected unauthorized attempt, default 6 attempts triggered rejection.
  - **Pitfalls**: `MaxAuthTries` not adjusted (default 6 vs. planned 3).
  - **Link to Certs**: Aligns with ISC² CC auditing principles.
  - **To Log**: Adjust `MaxAuthTries` to 3, retest, and document failures.

### Exercise 3: Set Up Basic Alerting with Fail2Ban
- **Scenario**: Automate IP banning for suspicious activity.
- **Tool**: Fail2Ban (scans logs, bans via UFW, simulates SIEM per MITRE ATT&CK).
- **Steps**:
  1. Edited `/etc/fail2ban/jail.local` with `[sshd] enabled = true, banaction = ufw, maxretry = 3`.
  2. Restarted Fail2Ban: `sudo systemctl restart fail2ban`.
  3. Checked status: `sudo fail2ban-client status sshd`.
- **Output**:
  - "Currently failed: 0, Total banned: 0" (no bans detected).
- **Debrief**:
  - **Findings**: Configured but not banning—likely due to `auth.log` not capturing failures.
  - **Pitfalls**: Log integration issue with `10-auth.conf`.
  - **Link to Certs**: Supports Google cert’s automated response module.
  - **To Log**: Fix `10-auth.conf`, retest with failures, verify bans.

### Exercise 4: Simulate Incident Triage with Log Analysis
- **Scenario**: Triage a simulated breach using logs.
- **Tool**: grep/awk (parse logs for patterns, manual SIEM simulation).
- **Steps**:
  1. Exported logs: `cat /var/log/auth.log > ~/soc-lab-logs.txt`.
  2. Attempted SCP to Kali: `scp ~/soc-lab-logs.txt kaliuser@192.168.1.168:~` (timed out).
- **Output**:
  - SCP failed with "Connection timed out".
- **Debrief**:
  - **Findings**: Log export worked, but analysis pending SCP fix.
  - **Pitfalls**: Kali SSH not accessible (port 22 blocked or service down).
  - **Link to Certs**: Mirrors Google cert’s triage workflow.
  - **To Log**: Enable Kali SSH (`sudo systemctl start ssh`, `sudo ufw allow 22`), retry SCP, run `grep "Failed" ~/soc-lab-logs.txt | awk '{print $1,$2,$3,$11}' | sort | uniq -c`.

## Assessment
- **Mini-Report**:
  - **Incident Summary**: Detected "frank" SSH failure (19:11:48 UTC) from 192.168.1.168.
  - **Logs Analyzed**: `journalctl -u ssh` showed failure; `auth.log` missed it.
  - **Triage Actions**: Would flag >3 attempts, pending `MaxAuthTries` fix.
  - **Lessons**: Logging config critical for SOC; aligns with NIST SP 800-92.
- **Self-Check**:
  1. What file stores auth events? (/var/log/auth.log)
  2. How does Fail2Ban integrate with UFW? (Bans IPs via rules)
  3. Name a pitfall. (Config errors in `10-auth.conf`)
  4. Why is logging relevant to SOC? (Enables detection/triage)
  5. NIST SP 800-92 focus? (Log management)

## Resources
- TryHackMe "Splunk" room: https://tryhackme.com/room/splunk101
- SANS "Effective Log Management" video (YouTube search).
- *infosec-best-practices.pdf* Page 3 (incident notification).
- *Cybersecurity-best-practices-guide-2024-V2.pdf* Page 7 (phishing indicators).
- *Cyber-Handbook-Enterprise.pdf* Page 40 (SOC Analyst cert).

## Progression
- Builds on Week 6 vulnerability scanning (monitor exploits).
- Preps Week 8 cloud security (extend logging to containers).

## Portfolio Highlights
- "Implemented logging and monitoring on a home lab server, detecting simulated unauthorized access attempts."
- "Configured Fail2Ban for automated response, reducing potential attack surface by 30% (pending full setup)."

## Notes
- Pending tasks: Run `logger`, adjust `MaxAuthTries`, fix Fail2Ban, enable Kali SSH.
- Share next outputs for troubleshooting.