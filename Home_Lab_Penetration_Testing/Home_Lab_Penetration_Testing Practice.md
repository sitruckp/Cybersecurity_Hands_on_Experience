# Home Lab Penetration Testing Practice – Overview

## Purpose
This repository documents my structured, **ethical self-study** in penetration testing (pen-testing) skills using a fully isolated home lab.  

The goal is to build foundational knowledge and hands-on experience in a safe, legal environment — preparing for a potential **university penetration testing / red team opportunity**.  

**Everything is 100% contained to my own systems.** No external networks, no production systems, no unauthorized targets — ever.

## Scope & Rules of Engagement (RoE)
- **In-scope assets** — only the following machines in my home lab, connected via a private SoftEther VPN and/or local subnet:
  - Kali Linux laptop (attacker / control station)
  - Ubuntu laptop
  - Windows laptop (with WSL)
  - Ubuntu server
  - Debian server
- **Out-of-scope** — anything else: university networks, home router admin interface (unless explicitly added later as a lab target), cloud services, neighbor devices, internet-facing IPs, etc.
- All activities follow a self-imposed **Rules of Engagement** mindset:
  - Define scope mentally before every session
  - No destructive actions (even in lab)
  - No permanent denial-of-service simulations unless explicitly isolated and reversible
  - Document everything
  - Clean up / revert changes after exploitation practice
- Tools used: Nmap, Wireshark, Metasploit, Lynis, Fail2Ban, Auditd, ELK Stack (and others added later)

## Structure of the Practice Plan
4-week progressive program (5 sessions/week, 1–2 hours each) — total 20 sessions.

- **Week 1**: Reconnaissance & Network Discovery  
  (Low-risk info gathering — mostly passive & light active scanning)
- **Week 2**: Vulnerability Scanning & Assessment  
  (Finding weaknesses without exploitation)
- **Week 3**: Safe Exploitation & Post-Exploitation  
  (Controlled, reversible demos on isolated lab targets)
- **Week 4**: Reporting, Mitigation & Defense  
  (Documenting findings, hardening systems, blue-team perspective)

Each session includes:
- Warm-up (key cybersecurity term/concept review)
- 4–6 step-by-step activities with copy-paste commands
- Safety notes & verification steps
- Reflection questions tying back to real-world/university contexts

## Why Document This Publicly (on GitHub)?
- Personal accountability and organization
- Build a clean, ethical portfolio piece (redact sensitive IPs/hostnames before sharing broadly)
- Help others learning ethical hacking in home labs
- Practice clear technical writing — a key skill for pen-test reports

**Last updated:** February 2026  
**Author:** K. (State College, PA)  
**License:** MIT (feel free to fork/adapt for your own ethical lab practice)

See the `week1/` folder (and future week folders) for session notes.