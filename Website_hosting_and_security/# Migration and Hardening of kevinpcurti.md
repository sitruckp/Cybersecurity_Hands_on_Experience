# Migration and Hardening of kevinpcurtis.com

## Overview
This document chronicles the migration of `kevinpcurtis.com` from Weebly to a self-hosted Ubuntu server, performed on November 22, 2025. The process involved setting up a static IP, installing Nginx, transferring Weebly files, securing the server, and preparing for HTTPS. This project enhances cybersecurity skills, including server administration, DNS management, and hardening, aligning with ISC2 CC, Google Cybersecurity Analyst, and IBM Cybersecurity Analyst certifications.

## Timeline
- **Start**: ~12:00 PM EST, November 22, 2025
- **Completion**: ~05:47 PM EST, November 22, 2025
- **Duration**: ~5.5 hours

## Achievements

### 1. Initial Server Setup
- **Static IP Configuration**:
  - Assigned `192.168.1.183` to the Ubuntu server (`labserver`).
  - Verified connectivity within the local network.
- **Nginx Installation**:
  - Installed Nginx: `sudo apt install nginx`.
  - Resolved port 80 conflict with Apache: Stopped Apache (`sudo systemctl stop apache2`) and ensured Nginx owned port 80.
- **Verification**:
  - Confirmed Nginx running: `sudo systemctl status nginx`.

**Cybersecurity Tie-In**: Securing port ownership prevents unauthorized service conflicts, a key access control principle.

### 2. File Transfer from Weebly
- **Source Verification**:
  - Identified Weebly files in `/home/kevin/weebly_site/323758492784178768-1763335693/728186611691a5dcc49427/` on `kevin-HP-Laptop-17-by1xxx`.
  - Listed contents: `ls -l /home/kevin/weebly_site/323758492784178768-1763335693/728186611691a5dcc49427/`.
- **SCP Transfer**:
  - Adjusted command: `scp -r -P 2222 /home/kevin/weebly_site/323758492784178768-1763335693/728186611691a5dcc49427/* kevin@192.168.1.183:/var/www/html/`.
  - Fixed permissions on server: `sudo chown -R kevin:kevin /var/www/html` (temporary), reverted to `sudo chown -R www-data:www-data /var/www/html`.
- **Deployment**:
  - Verified files in `/var/www/html/` with `ls -l`.
  - Tested site at `http://192.168.1.183` with `curl http://192.168.1.183`.

**Cybersecurity Tie-In**: Using SCP over SSH encrypts file transfers, protecting against eavesdropping.

### 3. DNS Configuration
- **Public IP**:
  - Identified server’s public IP: `98.49.48.35` via `curl ifconfig.me`.
  - Set up port forwarding on Linksys AX3200 for ports 80 and 443 to `192.168.1.183`.
- **DNS Update**:
  - Updated A records at Weebly:
    - `@` → `98.49.48.35`
    - `www` → `98.49.48.35`
    - TTL: 600 seconds.
  - Verified propagation: `ping kevinpcurtis.com` resolved to `98.49.48.35` by ~03:28 PM EST.

**Cybersecurity Tie-In**: Proper DNS management prevents hijacking, a common attack vector.

### 4. Server Hardening
- **Nginx Hardening**:
  - Disabled server tokens: Added `server_tokens off;` in `/etc/nginx/nginx.conf` under `http {}`.
  - Added security headers in `/etc/nginx/sites-available/default`:
    - `add_header X-Frame-Options "DENY";`
    - `add_header X-Content-Type-Options "nosniff";`
    - `add_header Content-Security-Policy "default-src 'self'";`
  - Restricted methods: Added `if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }`.
  - Limited request size: Added `client_max_body_size 10m;` in `nginx.conf`.
  - Added rate limiting: `limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;` in `nginx.conf`, `limit_req zone=mylimit burst=20;` in `server {}`.
  - Verified with `curl -I` and `curl -X PUT` (405 response).
- **Firewall Setup**:
  - Installed `ufw`: `sudo apt install ufw`.
  - Set defaults: `sudo ufw default deny incoming` and `allow outgoing`.
  - Allowed ports: `sudo ufw allow 80/tcp`, `sudo ufw allow 443/tcp`, `sudo ufw allow 2222/tcp`.
  - Enabled: `sudo ufw enable`.
  - Blocked unused port 25 (Postfix): `sudo ufw deny 25/tcp`, stopped/masked Postfix.
  - Verified with `sudo ufw status` and `sudo netstat -tulnp`.

**Cybersecurity Tie-In**: Hardening and firewall rules reduce the attack surface, aligning with least-privilege and defense-in-depth principles.

### 5. SSL Preparation
- **Certbot Installation**:
  - Installed: `sudo apt install certbot python3-certbot-nginx`.
  - Verified: `certbot --version` showed 2.9.0.
- **Next Step**: Obtain SSL certificate with `sudo certbot --nginx -d kevinpcurtis.com -d www.kevinpcurtis.com`.

**Cybersecurity Tie-In**: SSL will encrypt traffic, protecting against man-in-the-middle attacks.

## Pending Tasks
- **SSL Certificate**: Run Certbot to enable HTTPS.
- **Site Testing**: Verify functionality at `https://kevinpcurtis.com`.
- **Optional Enhancements**: Firewall tuning (e.g., restrict SSH), additional Nginx hardening.

## Conclusion
This migration transformed `kevinpcurtis.com` into a self-hosted, secured site, completed in under 6 hours. The process honed skills in server setup, file transfer, DNS management, and security hardening, preparing for real-world cybersecurity challenges.

## Timestamp
- **Documented**: 05:47 PM EST, November 22, 2025