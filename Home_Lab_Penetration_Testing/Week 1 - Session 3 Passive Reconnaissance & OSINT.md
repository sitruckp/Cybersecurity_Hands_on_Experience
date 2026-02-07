# Pen-Testing Practice Log: Week 1, Session 3 – Passive Reconnaissance & OSINT

**Date:** February 7, 2026  
**Location:** Home Lab   
**Session Duration:** ~1.5–2 hours  
**NIST CSF Alignment:** Identify – Asset Management & Risk Assessment (gathering public info on assets without interaction)

## Session Goal
Practice purely **passive reconnaissance** using open-source intelligence (OSINT) tools. No packets sent to lab targets. Focus on:
- WHOIS lookups
- DNS record enumeration (dig)
- OSINT aggregation with theHarvester
- Google dorks for exposed documents
- Verifying passivity with Wireshark

This builds foundational skills for real-world engagements where attackers start with public data before active scanning.

## Tools Used
- Kali Linux (attacking machine)
- Terminal commands: `whois`, `dig`, `theHarvester`
- Browser: Firefox + Google dorks
- Wireshark (to confirm no traffic to lab IPs)

## Targets (for demonstration only – passive, public sources)
- Personal domain: `kevinpcurtis.com` (low footprint, privacy-protected)
- University-like domain: `monmouth.edu` (larger institutional footprint – simulated employer target)

## Key Activities & Findings

### 1. WHOIS Lookup
- Command: `whois kevinpcurtis.com`
- Findings (kevinpcurtis.com):
  - Registered 2016-02-04 via Automattic (WordPress.com)
  - Privacy protected (Knock Knock WHOIS Not There, LLC)
  - Proxy email: kevinpcurtis.com@privatewho.is
  - Name servers: WordPress.com trio

### 2. DNS Enumeration (dig)
- MX: Google Workspace (aspmx.l.google.com priority 10, etc.)
- TXT: None (no SPF/DMARC → potential spoofing risk)
- NS: ns1/2/3.wordpress.com
- ANY query timed out (normal behavior)

### 3. theHarvester OSINT Aggregation
- Command: `theHarvester -d kevinpcurtis.com -b all -l 500`
- Troubleshooting:
  - Many sources failed due to missing API keys (Bevigil, Censys, Shodan, etc.)
  - Added note: Edit `/etc/theHarvester/api-keys.yaml` for future runs
- Results (limited):
  - Subdomain: mail.kevinpcurtis.com
  - IPs: 199.34.228.X, 199.34.228.X, 216.21.224.X

- Extended run on `monmouth.edu`:
  - ~500 emails (e.g., rcarsey@monmouth.edu, sonn@monmouth.edu)
  - Hundreds of subdomains (vpn.monmouth.edu, ecampus.monmouth.edu, docker.monmouth.edu containers, etc.)
  - Dynamic IP ranges: 192.154.128.x, 204.152.148.x, 192.100.64.x

### 4. Google Dorks (Browser-based)
- Ran in Firefox (not terminal!)
- Key queries & approximate results for monmouth.edu:
  - `site:monmouth.edu filetype:pdf` → ~9,200 results
  - `site:monmouth.edu filetype:pdf "password"` → ~134
  - `site:monmouth.edu filetype:pdf intext:"confidential"` → ~189
  - `site:monmouth.edu inurl:admin` → ~48
  - `site:monmouth.edu "powered by"` → ~2,440 (software/version hints)

### 5. Passivity Verification
- Used Wireshark:
  - Captured during commands/dorks
  - Filtered: `ip.dst == <Ubuntu IP> or ip.dst == <Debian IP>`
  - Result: Zero packets to lab targets → confirmed 100% passive

## Generated Deliverables
- Two Markdown OSINT reports created:
  - `kevinpcurtis-com-osint-report.md`
  - `monmouth-edu-osint-report.md`
- These will be committed to repo for portfolio evidence.

## Lessons Learned & Troubleshooting
- theHarvester command is case-sensitive: `theHarvester` (not `theharvester`)
- Google dorks must be run in browser search bar, not terminal
- Missing API keys limit theHarvester → plan to sign up for free tiers (Shodan, Hunter.io) next time
- Privacy services (e.g., WordPress proxy) reduce personal exposure
- Universities have massive public footprints → PDFs, emails, subdomains are gold for attackers

## Reflection Questions
1. What differences in exposure did you notice between a personal domain (kevinpcurtis.com) and an institutional one (monmouth.edu)?
2. How could an attacker use the exposed emails and subdomains from monmouth.edu in a university phishing campaign?
3. Why is verifying passivity (Wireshark check) a critical habit even in low-risk recon?

## Next Steps
- Week 1 Session 4: Active network discovery (safe ping sweeps, ARP in lab only)
- Add API keys to theHarvester for deeper OSINT
- Commit this log + reports to GitHub

**Rules of Engagement Reminder:** 100% lab-only, isolated subnet/VMs, no external/unauthorized targets. Ethical practice only.

---
K. – Ethical Pen-Testing Practice Log  
Home Lab | Kali → Ubuntu/Debian/Windows targets via SoftEther VPN  
February 7, 2026