# Week 5: Identity and Access Management Progress Report

## Overview
Week 5 focuses on Identity and Access Management (IAM), implementing Role-Based Access Control (RBAC) and Multi-Factor Authentication (MFA) in my home lab. The Ubuntu server serves as the target, and Kali as the analyst workstation. This report documents setup, exercises, troubleshooting, and lessons learned, aligning with ISC² CC and Google Cybersecurity cert skills.

**Date**: December 01, 2025  
**Lab Setup**: Kali on Lenovo ThinkPad Edge E520; Hardened Ubuntu server on HP 14 (IP: 192.168.0.102, SSH port: 2222).  

## Objectives
- Configure RBAC on Ubuntu to restrict user privileges.
- Implement MFA for SSH access.
- Simulate unauthorized access and analyze results.

## Prerequisites
- Update Ubuntu: `sudo apt update && sudo apt upgrade -y`
- Install tools: `sudo apt install libpam-google-authenticator` (for MFA on Ubuntu); `sudo apt install hydra` (on Kali for testing).

## Exercise 1: Recreate Analyst User (Setup Refresh)
**Scenario**: Debian server from Week 1 is non-functional; switched to Ubuntu. Recreated non-root 'analyst' user for safe IAM testing.

**Steps**:
1. Create user: `sudo adduser analyst` (set strong password).
2. Add to sudo group: `sudo usermod -aG sudo analyst`.
3. Test: `su - analyst` then `sudo whoami` (outputs "root").

**Output**: User created successfully; sudo privileges confirmed.

**Debrief**: Logged in `/home/analyst/setup.log`. Builds on least privilege from infosec-best-practices.pdf (Page 2). Pitfall: Weak passwords—used 12+ chars mix.

## Exercise 2: SSH Key-Based Authentication for Analyst
**Scenario**: Secure remote access to prevent brute-force attacks.

**Tool**: `ssh-keygen` and manual key copy (due to `ssh-copy-id` issues).

**Steps** (from Kali):
1. Generate key: `ssh-keygen -t ed25519 -C "analyst@kali"` (overwrote existing; set passphrase).
2. Transfer public key: `scp -P 2222 /home/kcurtis/.ssh/id_ed25519.pub kevin@192.168.0.102:/tmp/id_ed25519.pub`.
3. On Ubuntu (as kevin): 
   - `sudo mkdir -p /home/analyst/.ssh`
   - `sudo chmod 700 /home/analyst/.ssh`
   - `sudo sh -c 'cat /tmp/id_ed25519.pub >> /home/analyst/.ssh/authorized_keys'`
   - `sudo chown -R analyst:analyst /home/analyst/.ssh`
   - `sudo chmod 600 /home/analyst/.ssh/authorized_keys`
4. Test login: `ssh -i /home/kcurtis/.ssh/id_ed25519 -p 2222 analyst@192.168.0.102`

**Outputs and Troubleshooting**:
- Key generation fingerprint: SHA256:4Vs375BSusf4wgbrUf8haUIrV6kzbr1dkkOkpxKLGuA
- `ssh-copy-id` error: "Too many arguments" — worked around with manual copy.
- SSH error: "Permission denied (publickey)" — fixed permissions and config.
- "Too many authentication failures" — used `-o IdentitiesOnly=yes` to specify key.
- Verified Ubuntu `/etc/ssh/sshd_config`: PubkeyAuthentication yes; restarted SSH.

**Debrief**: Logged in `/home/kcurtis/lab_notes.txt`. Pitfall: Path errors in key append—ensured correct source/destination. Ties to Cybersecurity-best-practices-guide-2024-V2.pdf (Page 17) password tips.

## Exercise 3: RBAC Configuration (In Progress)
**Scenario**: Limit 'analyst' privileges using sudoers.

**Steps** (planned):
1. `sudo visudo`
2. Add: `analyst ALL=(ALL) /usr/bin/cat, /usr/bin/less`
3. Test: `sudo cat /var/log/syslog` (allowed); `sudo rm /tmp/test` (denied).

**Status**: Pending successful SSH access as analyst.

## Assessment
**Self-Check Quiz**:
1. What command adds a user to sudo group? (`usermod -aG sudo analyst`)
2. Why use key-based SSH? (Resists brute-force; aligns with MITRE ATT&CK T1110 mitigation)
3. Common pitfall in sudoers? (Syntax errors—use visudo to validate)

**Mini-Report**: Troubleshooting strengthened understanding of auth failures; reduced risk by implementing keys.

## Resources
- [Ubuntu SSH Guide](https://ubuntu.com/tutorials/ssh-keygen-on-ubuntu)
- Reference: infosec-best-practices.pdf (Page 2, Human Resources Security)
- TryHackMe: IAM Basics room

## Lessons Learned and Portfolio Tip
Overcame key auth issues, applying defense-in-depth. Add to GitHub: "Implemented secure IAM with SSH keys and RBAC, troubleshooting auth failures in lab."

**Next Steps**: Complete RBAC and MFA; share `/var/log/auth.log` snippets.
```

