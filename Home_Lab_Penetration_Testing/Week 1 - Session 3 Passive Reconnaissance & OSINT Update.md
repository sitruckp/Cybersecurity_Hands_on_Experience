# Pen-Testing Practice Log: Week 1, Session 3 – Passive Reconnaissance & OSINT (Update)

**Date:** February 8, 2026  
**Location:** Home Lab (State College, PA)  
**Session Duration:** ~1 hour (follow-up / troubleshooting)  
**NIST CSF Alignment:** Identify – Asset Management, Information Protection, Risk Assessment (public exposure mapping)

## Update Overview
After the initial Session 3 run, I added two free API keys to improve theHarvester results:
- Hunter.io (for professional email discovery)
- Censys.io (for subdomain, certificate, and IP discovery)

This was a direct follow-up to fix missing API key errors and deepen passive OSINT gathering. All activity remained 100% passive—no packets sent to lab targets.

## Key Changes & New Results
### theHarvester Rerun Command


### What Improved with API Keys
- **Hosts/Subdomains**: Jumped from ~500 to **4,594**  
  - Massive increase in dynamic/student hosts: e.g., 130-156-080-000.dyn.xxxxxxxxxxx.edu → 130-156-080-255.dyn.xxxxxxxxxxx.edu  
  - New static ones: speedtest1.xxxxxxxxxxx.edu, remote.xxxxxxxxxxx.edu, mymu.xxxxxxxxxxx.edu, phone.xxxxxxxxxxx.edu, sigmataugamma.xxxxxxxxxxx.edu, vpngw1.xxxxxxxxxxx.edu  
  - Many Docker-related: ollama.docker.xxxxxxxxxxx.edu, gpt-researcher.docker.xxxxxxxxxxx.edu, etc.  
  → Likely driven by **Censys.io** scanning Certificate Transparency Logs.

- **IPs Found**: 31 new/curated IPs (including AWS, Cloudflare IPv6, Vercel, Bluehost)  
  → Better cloud/hosting visibility than previous run.

- **Interesting URLs**: 31 newly highlighted (e.g., outlook.xxxxxxxxxxx.edu, federation.xxxxxxxxxxx.edu/adfs/ls login, uptime.docker.xxxxxxxxxxx.edu/dashboard, portainer.docker.xxxxxxxxxxx.edu)  
  → Potential exposed dashboards or login pages.

- **ASNs**: 6 discovered (Cloudflare, Amazon, NJEDge.Net, etc.)  
  → Helps map network ownership.

- **Hudson Rock (no key needed)**: 152 compromised credentials (48 employees, 104 users) from infostealer logs.

- **Emails**: Still 0 found (Hunter.io did not yield results for this domain—possibly low public exposure or rate limit).

### What Stayed the Same / Limited
- Many sources still failed (Bevigil, Bufferoverun, Brave, GitHub, BuiltWith, SecurityScorecard) due to missing keys.
- No people/LinkedIn users found.
- BuiltWith continued to error (mimetype issue—common with free tier).

## Potential Risks & Exposure Highlights (xxxxxxxxxxx.edu)
No direct CVEs or exploitable vulns were confirmed (passive recon can't probe services), but the following attack surface was revealed:

1. **Extensive Subdomain Footprint** (4,594 hosts)  
   - Risk: Subdomain takeover (abandoned cloud resources), forgotten test/dev services, shadow IT.

2. **Dynamic/Student Hosts**  
   - Risk: Individual machines potentially leaking data or serving as pivot points if compromised.

3. **Exposed Management Interfaces**  
   - e.g., Portainer, Uptime dashboards, ADFS login endpoints  
   - Risk: If not properly authenticated/restricted → unauthorized access.

4. **Credential Compromise Signals** (152 total)  
   - Risk: Credential stuffing, targeted phishing using combined email + breach data.

5. **Cloud & IPv6 Exposure**  
   - Risk: Misconfigured cloud buckets, overlooked IPv6 firewall rules.

All risks are theoretical until active scanning confirms them (Week 2).

## Troubleshooting & Lessons Learned
- **Hunter.io not yielding emails**: Possible causes → domain has low public email footprint, free tier rate limit hit, or config syntax issue.  
  → Next test: Run on tesla.com or my own domain (kevinpcurtis.com) to verify.
- **YAML config**: Confirmed correct indentation and format in `/etc/theHarvester/api-keys.yaml`.
- **Key activation**: Censys clearly worked (huge subdomain jump); Hunter needs validation.
- **Plan**: Add Shodan next for exposed service intel.

## Updated Deliverables
- Previous OSINT reports (kevinpcurtis-com & xxxxxxxxxxx-edu) remain valid but now outdated for xxxxxxxxxxx.edu volume.
- New theHarvester output saved as HTML for review.
- This log entry documents API key impact and risk analysis.

## Reflection Questions
1. How did adding Censys change the perceived attack surface compared to the first run?
2. Why might Hunter.io return 0 emails for xxxxxxxxxxx.edu when universities often have public directories?
3. In a university pen-test, how would this level of subdomain exposure guide the next phase (scanning)?

## Next Steps
- Validate Hunter.io on a different domain.
- Add Shodan API key for future runs.
- Move to Week 1 Session 4: Active network discovery (safe ping/ARP in isolated lab).

**Rules of Engagement Reminder:** 100% ethical, lab-isolated only. No external targets scanned or probed.

---
K. – Ethical Pen-Testing Practice Log  
Home Lab | Kali → Ubuntu/Debian/Windows targets via SoftEther VPN  
February 8, 2026