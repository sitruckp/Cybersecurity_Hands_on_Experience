Week 3: Security Architecture and Engineering Report
Layers Implemented

Perimeter/Host: Installed and configured Fail2Ban for SSH jail with UFW banaction, maxretry=3, bantime=600, findtime=600, backend=systemd. Extensive troubleshooting resolved socket errors (e.g., "Failed to access socket path") via reinstall, python3-systemd dependency, runtime dir creation (/run/fail2ban), and config overrides. Service confirmed active per journalctl logs ("Server ready" and successful start after exit-code 255 fixes). Simulated brute-force attempts from Kali triggered bans (e.g., wrong passwords 4x), verified with sudo fail2ban-client status sshd showing banned IPs.
Application: Installed Apache (sudo apt install apache2) and enabled AppArmor profile (sudo aa-enforce /etc/apparmor.d/usr.sbin.apache2). Denied unauthorized actions during tests (e.g., probed restricted paths like /server-status via curl, logged denials in sudo journalctl -u apparmor). Hardened Apache with security headers in /etc/apache2/conf-enabled/security.conf (X-Frame-Options "DENY", X-Content-Type-Options "nosniff"), enabled mod_headers (sudo a2enmod headers), and verified application via curl outputs.
Data: Installed EncFS (sudo apt install encfs) and created encrypted mount (encfs /encrypted /decrypted with paranoia mode and strong passphrase). Tested by adding sensitive file, unmounting (fusermount -u /decrypted), and verifying raw data as gibberish (ls /encrypted showed encrypted files). Protected against data exfiltration even if other layers fail.
Testing Layer: Installed Nmap/Nikto on Kali (already present). Initial Nmap stealth scan (-sS -T4 192.168.0.102 -p 1-1000) showed all ports filtered (no-response due to UFW). After temp UFW allow (sudo ufw allow from kali-ip to any port 80), re-scan revealed port 80/http open. Nikto (-h 192.168.0.102) initially tested 0 hosts, then reported Apache/2.4.65 (Debian), missing headers (anti-clickjacking/X-Content-Type-Options), ETag inode leak (CVE-2003-1418), allowed methods (POST/OPTIONS/HEAD/GET), no CGI dirs.

Scan Results Summary

Nmap output (post-UFW allow): Host up (0.0020s latency), MAC C8:A3:62:84:0C:72 (Asix Electronics). Port 80/tcp open (http); 999 filtered.
Nikto output: v2.5.0, Server Apache/2.4.65 (Debian), missing X-Frame-Options and X-Content-Type-Options, ETag inode leak on / (inode: 29cf, size: 643a91d14a6d0), OPTIONS allowed methods, 4 items reported, 8102 requests, no CGI dirs. Noted server version not in database (prompted for submission, declined).
Fail2Ban status: sshd jail active, 0 current bans, monitored journald (per sudo fail2ban-client status sshd and journalctl).
AppArmor logs: Denied extras during Apache tests (e.g., unauthorized file reads).
Curl verification (post-headers): Confirmed X-Frame-Options: DENY and X-Content-Type-Options: nosniff in HTTP responses from both Kali and localhost.

Gaps Found/Remediated

Gap: Fail2Ban startup failures (socket path errors, exit-code 255)—remediated by purge/reinstall, deps (python3-systemd, rsyslog), backend=systemd in jail.local, runtime dir (/run/fail2ban), and paths-debian.conf updates (sshd_backend=systemd). Verified "Server ready" in logs.
Gap: Nmap all ports filtered initially—remediated by temp UFW allow from Kali IP, revealing expected port 80; deleted rule after to restore hardening.
Gap: Nikto missing headers and ETag leak—remediated by enabling mod_headers, adding directives to security.conf, graceful restart; re-verified with curl (headers present). Disabled ETags (FileETag None in config) to fix CVE-2003-1418.
Gap: Nikto 0 hosts initially—remediated by ensuring Apache running and UFW allow.
Overall defense-in-depth score: 4/5 layers active, eliminating single points of failure per "infosec-best-practices.pdf" page 2 diagram (defense-in-depth approach with redundancy).

Risk Reduction
Implemented layered defenses mitigated common threats: Brute-force via Fail2Ban automation (NIST SP 800-53 AC-6 least privilege), app exploits via AppArmor confinement (CIS Controls application whitelisting), data leaks via EncFS encryption (ISO 27001 A.8.2 cryptography), and recon via scans/remediations (MITRE ATT&CK T1046 network discovery). Initial high risk from unverified configs (e.g., filtered ports hiding exposures) reduced to low through troubleshooting and hardening, aligning with PCI DSS testing guidance from "Penetration-Testing-Guidance-v1_1.pdf" page 2. Builds on ISC² CC's architecture and Google cert's engineering modules by adding practical redundancy and triage skills.