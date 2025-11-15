Cybersecurity Hands-On Lab Portfolio
Overview
This repository serves as my personal archive of hands-on cybersecurity projects, artifacts, and learning plans. As I transition from educational technology and bio-defense into cybersecurity (with certifications like ISC2 CC and Google Cybersecurity Professional, plus ongoing IBM Analyst and CompTIA Sec+ prep), I'm documenting practical labs in a Kali + Debian environment. The focus is on ethical, isolated setups for skills like server hardening, vulnerability scanning, network analysis, and incident triage. All activities are lab-confined to ensure safety and compliance.
Key goals:

Build portfolio evidence for interviews (e.g., logs, reports, configurations).
Track progress with metrics like Lynis scores or risk mitigations.
Merge insights from multiple LLM-generated plans for a customized 10-week SOC analyst journey.

Repository Structure

/plans/: LLM-generated 10-week learning plans and analyses.
10-week hands-on learning plan.md: Detailed plan with portfolio tips and tools like Lynis/Nmap.
10-Wk_Hands-on_Cybersecurity_Learning_Plan.md: NIST/Mitre-focused plan with residual risk tables.
Ethical_Hacking_Hand-on-Experience_10-wk_Grok.md: Hacking-oriented plan with resources like TryHackMe.
LLM_Plan_Analysis.md: My comparative analysis of the three plans, highlighting strengths/weaknesses for merging.

/hardening-guides/: Step-by-step Markdown guides for server setups.
Debian-Server-Build.md: Comprehensive hardening walkthrough (e.g., UFW, Fail2Ban, Auditd) with verifications.

/artifacts/: Lab outputs and evidence (redacted for PII).
Lynis logs (e.g., lynis_audit.log): Baseline and post-hardening scans.
Wireshark captures (e.g., ssh_capture.pcap): Network traffic analysis.
Metasploit logs: Ethical testing results.
Risk registers/reports: Week-specific Markdowns like asset inventories or incident runbooks.

/scripts/: Simple tools for audits/parsing (e.g., parser.py for logs).

Prerequisites for Replicating Labs

Debian 13 server (hardened as per guides).
Kali Linux VM/workstation.
Tools: Install via sudo apt install lynis nmap wireshark fail2ban auditd metasploit-framework (adjust per plan).
GitHub Desktop on Windows for easy uploads (as used for artifacts).
Ethical mindset: All testing is self-contained; no external targets.

How to Use This Repo

Clone Locally: Use GitHub Desktop or git clone to pull the repo.
Follow Plans: Start with Week 1 across plans (risk management with Lynis/CIA Triad). Run commands on your lab setup.
Generate Artifacts: Capture outputs (e.g., sudo lynis audit system > lynis.log) and add to /artifacts/.
Track Progress: Update README with your Lynis score improvements or mitigated risks.
Commit/Push: Stage files in GitHub Desktop, commit with messages like "Added Week 1 risk register," and push.

Example Workflow:

Harden server: Follow Debian-Server-Build.md steps (e.g., enable UFW with sudo ufw enable).
Verify: Run sudo ufw status and log results.
Analyze: Use LLM_Plan_Analysis.md to pick best exercises (e.g., Plan 3's Hydra sim for IAM testing).

Resources Integrated

Frameworks: NIST RMF, CIS Benchmarks, MITRE ATT&CK.
Learning Paths: TryHackMe SOC Level 1, HackTheBox labs.
News/Digests: Inspired by daily cybersecurity summaries from sources like Cybernews/CSO Online.

This repo evolves with my labs—feel free to fork for your own journey.
