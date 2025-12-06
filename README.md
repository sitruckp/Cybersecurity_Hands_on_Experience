# Cybersecurity Hands-On Lab Portfolio

## Overview
This repository serves as my personal archive of hands-on cybersecurity projects, artifacts, and learning plans. As an aspiring cybersecurity professional with backgrounds in educational technology and bio-defense, I hold certifications like ISC2 CC and Google Cybersecurity Professional, with ongoing progress in IBM Cybersecurity Analyst and CompTIA Security+ prep. I'm documenting practical labs in a Kali + Debian environment, emphasizing ethical, isolated setups for skills like server hardening, vulnerability scanning, network analysis, incident triage, and now secure website hosting. My labs focus on ethical, isolated environments using Kali Linux, Debian/Ubuntu servers, and tools like ELK ElasticStack, Wireshark, Lynis, Metasploit, and Nikto, now incorporating secure web hosting and basic programming (Python, HTML) for security applications. All activities remain lab-confined to prioritize safety, compliance, and risk mitigation—aligning with frameworks like NIST RMF and CIS Benchmarks.

Recent achievements:
- Improved Lynis hardening score to 82 on Debian server via sysctl tweaks and service audits.
- Deployed ELK ElasticStack on Ubuntu laptop with Elastic Agents on Ubuntu labserver. 
- Completed a Python mini-course tailored for cybersecurity, with scripts for log parsing and web request analysis.
- Explored HTML for web vulnerability awareness, aligning with OWASP Top 10 mitigations.
- Deployed and secured a test website on Debian with Nginx, SSL/TLS (Certbot), and Nikto/OWASP ZAP scans.

Key goals:
- Build portfolio evidence for interviews (e.g., logs, reports, configurations, and web hosting security artifacts).
- Track progress with metrics like Lynis scores, risk mitigations, mitigated OWASP risks, incident response times and web vulnerability assessments.
- Merge insights from multiple LLM-generated plans for a customized 10-week SOC analyst journey, now incorporating secure web deployment and programming.

## Repository Structure
- **/plans/**: LLM-generated 10-week learning plans and analyses.
  - 10-week hands-on learning plan.md: Detailed plan with portfolio tips and tools like Lynis/Nmap.
  - 10-Wk_Hands-on_Cybersecurity_Learning_Plan.md: NIST/Mitre-focused plan with residual risk tables.
  - Ethical_Hacking_Hand-on-Experience_10-wk_Grok.md: Hacking-oriented plan with resources like TryHackMe.
  - LLM_Plan_Analysis.md: My comparative analysis of the three plans, highlighting strengths/weaknesses for merging.

- **/hardening-guides/**: Step-by-step Markdown guides for server setups, now including web hosting security.
  - Debian-Server-Build.md: Comprehensive hardening walkthrough (e.g., UFW, Fail2Ban, Auditd) with verifications.
  - Secure-Web-Hosting.md: Guide for deploying and securing a website on the Debian server (e.g., Apache/Nginx installation, SSL/TLS configuration via Let's Encrypt, access controls, and WAF basics). Includes risk assessments for common web vulnerabilities like OWASP Top 10 (e.g., injection, XSS).

- **/artifacts/**: Lab outputs and evidence (redacted for PII).
  - Lynis logs (e.g., lynis_audit.log): Baseline and post-hardening scans, including web-specific audits.
  - Wireshark captures (e.g., ssh_capture.pcap): Network traffic analysis, now with HTTP/HTTPS captures for web traffic inspection.
  - Metasploit logs: Ethical testing results, including web exploit simulations in isolated environments.
  - Risk registers/reports: Week-specific Markdowns like asset inventories, incident runbooks, and web hosting vulnerability scans (e.g., using Nikto or OWASP ZAP).
  - Web artifacts: Configuration files (e.g., nginx.conf snippets), SSL cert logs, and access/error logs from hosted site tests.

- **/scripts/**: Simple tools for audits/parsing (e.g., parser.py for logs), now with web-focused scripts like automated SSL renewal checks or log analyzers for suspicious web requests.

## Prerequisites for Replicating Labs
- Debian 13 server (hardened as per guides).
- Kali Linux VM/workstation.
- Tools: Install via `sudo apt install lynis nmap wireshark fail2ban auditd metasploit-framework apache2 nginx certbot nikto` (adjust per plan; add web tools like Certbot for SSL).
- GitHub Desktop on Windows for easy uploads (as used for artifacts).
- Ethical mindset: All testing is self-contained; no external targets. For web hosting, use local domains or self-signed certs initially to avoid production exposure.

## How to Use This Repo
1. Clone Locally: Use GitHub Desktop or `git clone` to pull the repo.
2. Follow Plans: Start with Week 1 across plans (risk management with Lynis/CIA Triad). Run commands on your lab setup.
3. Generate Artifacts: Capture outputs (e.g., `sudo lynis audit system > lynis.log`) and add to /artifacts/. For web hosting, deploy a test site via `sudo apt install nginx`, configure in /etc/nginx/sites-available/, and scan with `nikto -h localhost`.
4. Track Progress: Update README with your Lynis score improvements, mitigated risks, or web security metrics (e.g., reduced OWASP exposures).
5. Commit/Push: Stage files in GitHub Desktop, commit with messages like "Added Week 1 risk register" or "Updated web hosting artifacts post-SSL config," and push.

## Example Workflow
- Harden server: Follow Debian-Server-Build.md steps (e.g., enable UFW with `sudo ufw enable`).
- Verify: Run `sudo ufw status` and log results.
- Deploy secure website: Install Nginx (`sudo apt install nginx`), create a basic site in /var/www/html, enable SSL with Certbot (`sudo certbot --nginx`), and restrict access via .htaccess or Nginx configs.
- Analyze: Use LLM_Plan_Analysis.md to pick best exercises (e.g., Plan 3's Hydra sim for IAM testing, extended to web auth brute-force defenses). Scan the hosted site with Nikto or ZAP, mitigate findings (e.g., disable directory listing), and document in artifacts.
- Monitor: Set up Auditd rules for web logs (`auditctl -w /var/log/nginx/access.log -p wa`) and review for anomalies.

## Resources Integrated
- Frameworks: NIST RMF, CIS Benchmarks, MITRE ATT&CK, OWASP for web security.
- Learning Paths: TryHackMe SOC Level 1, HackTheBox labs, plus OWASP Web Security Testing Guide.
- News/Digests: Inspired by daily cybersecurity summaries from sources like Cybernews/CSO Online, with focus on web breaches (e.g., recent SQLi incidents).

## Future Steps as a Cybersecurity Professional
- Integrate advanced web security: Implement ModSecurity WAF, rate limiting, and CSP headers; test with simulated attacks in Metasploit.
- Expand monitoring: Add tools like OSSEC or ELK Stack for real-time web log analysis and alerting.
- Portfolio enhancement: Create a demo video of the hosted site under attack simulation (ethical, lab-only), with triage steps.
- Career tie-in: Use this for interview demos, e.g., "How I secured a web server against OWASP risks."
- Next lab phase: Week 5+ in plans—focus on incident response for web incidents, including forensics on captured traffic.

This repo evolves with my labs—feel free to fork for your own journey.