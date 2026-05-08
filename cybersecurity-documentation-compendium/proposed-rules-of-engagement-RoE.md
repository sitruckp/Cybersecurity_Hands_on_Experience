# Proposed Rules of Engagement (RoE) – Initial Cybersecurity Testing

**To:** Server Operations Director  
**CC:** Instructional Support Director  
**From:** Kevin Curtis (Instructional Designer / Cybersecurity Penetration Tester)  
**Date:** February 18, 2026  
**Subject:** Draft Rules of Engagement (RoE) for Monmouth University Penetration Testing / Vulnerability Scanning

## Purpose
This memo proposes a simple Rules of Engagement (RoE) for any initial testing. It is based on standard practices like NIST SP 800-115 and tailored as an internal document. This aligns with NIST Cybersecurity Framework (CSF) Govern and Protect functions.

## Objectives
- Identify vulnerabilities (e.g., known CVEs) in limited areas to meet insurance requirements and GLBA Safeguards Rule.
- Demonstrate risks safely without disrupting students, staff, or operations.
- Provide quick recommendations to improve security.

## Involved Team
- **Tester:** Kevin Curtis
- **Oversight:** Server Operations Director and designated lead
- **Emergency Contact:** IT On-Call

## Scope

**Allowed Areas:**
- External perimeter (public web servers or approved test URLs/IPs)
- Small internal test segment (non-production subnet via VPN)

**Not Allowed:**
- Student data systems
- Wireless or production systems during business hours
- Anything not explicitly listed

**Access:**
- Remote VPN or jump host (internal testing)
- Internet (external testing)

## Methodology and Tools
**Steps:**
1. OSINT – Passive Reconnaissance
2. Scanning (Nmap, OpenVAS)
3. Basic Demo / Proof-of-Concept (approved only – no real harm)

**Tools:**
- Kali Linux with Nmap, OpenVAS, Wireshark, Metasploit auxiliaries (no full exploits)

**No-Go Actions:**
- No Denial-of-Service (DoS)
- No changing or deleting data
- Stop immediately if anything seems off

## Timeline
- **Testing Window:** [e.g., Week of February 23, 2026]
- **Hours:** 8:30 am–4:45 pm or approved off-hours
- **Check-Ins:** Daily email update
- **Report:** Share findings within one week

## Safety Rules
- Pause immediately if any disruption occurs and notify oversight.
- Keep data secure: Anonymize reports, delete test logs after approval.
- Full transparency and ethical conduct.

## Reporting
Short format: Executive summary, findings list (risk + fix), positives.

## Approval
**Agreed by:**  
Kevin Curtis _______________________________ Date __________

**Reviewed/Approved by:**  
Server Operations Director _______________________________ Date __________