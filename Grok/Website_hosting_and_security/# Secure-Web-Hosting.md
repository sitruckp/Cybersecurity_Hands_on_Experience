# Secure-Web-Hosting.md

## Overview
As a cybersecurity professional building hands-on skills, this guide outlines deploying and securing a basic website on a hardened Debian 13 server. This extends our lab environment (Kali VM + Debian server) to include web hosting, focusing on ethical, isolated testing. We'll use Nginx (lightweight and performant; alternatives like Apache noted) to host a simple static site, implement SSL/TLS, apply access controls, and assess OWASP Top 10 risks. All steps prioritize least privilege, monitoring, and verification—aligning with NIST RMF and CIS Benchmarks.

Key objectives:
- Demonstrate secure web deployment for portfolio evidence (e.g., configs, scans, logs).
- Mitigate common vulnerabilities like injection, XSS, and misconfigurations.
- Track metrics: Pre/post-hardening scans (e.g., Nikto scores) and risk reductions.

**Assumptions:** Server is already hardened per Debian-Server-Build.md (UFW, Fail2Ban, Auditd enabled). Use a test site (e.g., HTML page in /var/www/html) in a lab VM—never expose to production without further controls.

## Step-by-Step Deployment and Hardening

### 1. Install Web Server (Nginx)
   - **Why Nginx?** Efficient for static sites, easy SSL integration; switch to Apache if dynamic content (PHP) is needed.
   - **Commands:**
     1. Update packages: `sudo apt update && sudo apt upgrade -y`
     2. Install: `sudo apt install nginx -y`
     3. Start and enable: `sudo systemctl start nginx` && `sudo systemctl enable nginx`
   - **Verification:** `sudo systemctl status nginx` (should show active). Browse to http://localhost in your VM browser—see default Nginx page.
   - **Risk Mitigation:** Remove default site if unused: `sudo rm /etc/nginx/sites-enabled/default`. This reduces unnecessary exposures (OWASP A05: Security Misconfiguration).

### 2. Configure Basic Site
   - Create a simple static site for testing.
   - **Commands:**
     1. Create directory: `sudo mkdir -p /var/www/my-lab-site/html`
     2. Set permissions: `sudo chown -R $USER:$USER /var/www/my-lab-site/html` (use www-data for production-like least privilege later).
     3. Add index.html: `echo "<html><body><h1>Secure Lab Site</h1></body></html>" | sudo tee /var/www/my-lab-site/html/index.html`
     4. Configure Nginx: Create `/etc/nginx/sites-available/my-lab-site` with:
        ```
        server {
            listen 80;
            server_name localhost;  # Use domain if applicable
            root /var/www/my-lab-site/html;
            index index.html;
            location / {
                try_files $uri $uri/ =404;
            }
        }
        ```
     5. Enable: `sudo ln -s /etc/nginx/sites-available/my-lab-site /etc/nginx/sites-enabled/`
     6. Test config: `sudo nginx -t`
     7. Reload: `sudo systemctl reload nginx`
   - **Verification:** Curl `curl http://localhost` or browse—see your page.
   - **Risk Mitigation:** Disable directory listing (already in config via try_files). Audit file permissions: `ls -l /var/www/` (ensure no world-writable).

### 3. Enable SSL/TLS with Let's Encrypt
   - **Why?** Encrypts traffic; prevents MITM (OWASP A02: Cryptographic Failures).
   - **Prerequisites:** For lab, use self-signed certs or local domain. For real certs, need a public domain (skip if fully isolated).
   - **Commands:**
     1. Install Certbot: `sudo apt install certbot python3-certbot-nginx -y`
     2. Obtain cert: `sudo certbot --nginx -d yourdomain.example.com` (replace with local for testing; use --dry-run first).
     3. Auto-renew: `sudo systemctl enable certbot.timer` && Test: `sudo certbot renew --dry-run`
   - **Alternative (Self-Signed for Lab):** `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt`
     Update Nginx config to listen 443 ssl, add ssl_certificate lines.
   - **Verification:** `curl https://localhost` (ignore self-signed warnings). Check cert: `openssl s_client -connect localhost:443`.
   - **Risk Mitigation:** Force HTTPS redirect in Nginx: Add `return 301 https://$host$request_uri;` to http server block.

### 4. Implement Access Controls and WAF Basics
   - **Why?** Limit exposure; defend against brute-force, XSS (OWASP A01: Broken Access Control, A03: Injection).
   - **Commands:**
     1. Firewall rules: `sudo ufw allow 'Nginx Full'` (allows HTTP/HTTPS).
     2. Basic auth: Install `sudo apt install apache2-utils -y`, then `sudo htpasswd -c /etc/nginx/.htpasswd user`, add to Nginx location: `auth_basic "Restricted"; auth_basic_user_file /etc/nginx/.htpasswd;`
     3. Rate limiting: In Nginx config, add `limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;` and `limit_req zone=mylimit burst=20;` to location.
     4. WAF Intro (ModSecurity): `sudo apt install libapache2-mod-security2 -y` (adapt for Nginx via libmodsecurity3), or use simple rules in Nginx (e.g., deny suspicious User-Agents).
   - **Verification:** Test auth: Curl with/without creds. Simulate requests: Use ab tool `ab -n 100 -c 10 http://localhost/`—check for 429 errors.
   - **Risk Mitigation:** Log accesses: Ensure `/var/log/nginx/access.log` is monitored via Auditd: `sudo auditctl -w /var/log/nginx/ -p wa -k web-log`.

### 5. Vulnerability Scanning and Risk Assessment
   - **Tools:** Nikto for basics, OWASP ZAP for advanced.
   - **Commands:**
     1. Install Nikto: `sudo apt install nikto -y`
     2. Scan: `nikto -h https://localhost -ssl` > nikto_scan.log
     3. Install ZAP (on Kali): `sudo apt install zaproxy -y`, run GUI, spider/scan site.
   - **Assessment Table (OWASP Top 10 Focus):**
     | Risk | Description | Mitigation | Verification |
     |------|-------------|------------|--------------|
     | A01: Broken Access Control | Unauthorized paths | Use auth, least privilege dirs | Check 403 on restricted URLs |
     | A03: Injection | User input flaws | Sanitize (static site low risk) | Test with sqlmap if dynamic |
     | A05: Security Misconfig | Default headers/exposures | Remove server banners: `server_tokens off;` in Nginx | Nikto scan for headers |
     | A07: Identification Failures | Weak auth | Strong passwords, Fail2Ban on /auth | Review Fail2Ban logs |
     | A08: Software Integrity | Outdated components | Regular apt updates | Lynis audit for web modules |
   - **Verification:** Review scan logs, mitigate high-severity items (e.g., disable TRACE method: `if ($request_method ~ ^(TRACE|TRACK)) { return 405; }`).
   - **Risk Mitigation:** Baseline vs. post-scan: Aim for 20%+ risk reduction. Document in /artifacts/.

## Monitoring and Incident Response
- Integrate with existing setup: Add web logs to Auditd/Fail2Ban.
- Simulate attacks: Use Metasploit (e.g., auxiliary/scanner/http/dir_scanner) in isolated lab—capture in Wireshark.
- Runbooks: Create simple Markdown for web incidents (e.g., "Block IP on suspicious access: sudo ufw insert 1 deny from IP").

## Future Steps
- Advanced WAF: Deploy full ModSecurity with OWASP CRS rules; test against simulated XSS.
- Dynamic Content: Add PHP/WordPress, harden with AppArmor profiles.
- Automation: Script scans (e.g., cron for Nikto weekly).
- Portfolio Tie-In: Add demo scripts showing breach simulation and response.
- Next Lab: Integrate with SOC plans—Week 4: Web traffic analysis in Wireshark.

This guide evolves with our labs—update as we test. Great progress on expanding your portfolio; this will shine in interviews for showing practical web sec skills.