# Penetration Testing  
## Rules of Engagement (RoE) – Initial Assessment

**Version:** 1.0  
**Date:** [Insert Date, e.g., February 2026]  
**Prepared by:** XXXXX XXXXX  
**Status:** Draft – For Review and Signature

### 1. Purpose and Objectives
This document establishes the Rules of Engagement for authorized penetration testing activities at XXXXXXXXX XXXXXXXXX. The goal is to identify vulnerabilities in designated systems to support cybersecurity insurance requirements, GLBA Safeguards Rule compliance, and overall security posture improvement—without causing disruption to university operations, student access, or staff workflows.

**Primary Objectives:**
- Discover and document known vulnerabilities (e.g., CVEs) in scope.
- Demonstrate potential risks through controlled, ethical testing.
- Provide actionable remediation recommendations.

### 2. Parties Involved
- **Tester / Practitioner:** XXXXX XXXXX  
  Certifications: ISC² Certified in Cybersecurity (CC), Google Cybersecurity Professional Certificate, pursuing CompTIA Security+, IBM Ethical Hacking with Open Source Tools  
  Contact: [Your Phone] | [Your Email]
- **Primary Approver:** XXXXX XXXXX – Director of Server Operations  
  Contact: XXXXX@XXXXXXX.XXX | XXX.XXX.XXXX
- **Secondary Approver:** XXXX XXXX – AVP & CIO  
  Contact: XXXXX@XXXXXXX.XXX
- **Emergency / On-Call Contact:** [Name / Role – e.g., IT Help Desk or on-duty admin]  
  Phone: [Number] | Email: [Email]

### 3. Scope
**In Scope:**
- External perimeter assets (e.g., public-facing web servers, approved URLs/IP ranges)
- Limited internal test subnet (e.g., 192.168.x.0/24 via VPN/jump host – if remote access granted)
- Specific systems agreed upon in writing prior to testing

**Out of Scope:**
- Production student information systems (e.g., Banner, Brightspace databases)
- Wireless networks during business/class hours
- Third-party hosted services (e.g., NJEdge infrastructure)
- Any system or network segment not explicitly listed and approved

**Access Method:** Remote via university-provided VPN or jump host from State College, PA

### 4. Testing Methodology and Tools
**Allowed Phases:**
1. Reconnaissance (passive OSINT, DNS lookups – no active touching/scanning)
2. Vulnerability Scanning (automated, non-disruptive – e.g., Nmap, OpenVAS)
3. Limited Exploitation (proof-of-concept only – if explicitly permitted in writing)
4. Post-Exploitation (minimal, stop at access demonstration)

**Tools to be Used:**
- Kali Linux-based toolkit: Nmap, Wireshark, OpenVAS/Greenbone, Metasploit (auxiliary modules preferred), Nikto, Burp Suite Community (if web scope)
- All tools run from isolated, controlled environment

**Prohibited Actions:**
- Denial-of-Service (DoS) or resource exhaustion attacks
- Data modification, deletion, or exfiltration
- Social engineering or phishing attempts
- Any action that could cause persistent changes without approval

### 5. Timeline and Scheduling
**Testing Window:** [Proposed dates, e.g., Week of March 2–6, 2026]  
**Allowed Times:** Off-hours preferred (8:00 PM – 6:00 AM ET, weekends) to minimize impact on students and staff  
**Daily Check-ins:** Brief status update via email or call by 9:00 AM following each session  
**Final Report Delivery:** Within 7 calendar days after last test session

### 6. Rules and Restrictions
- Testing must stop immediately if any unexpected disruption occurs (e.g., service slowdown, alert triggered).
- All captured data (logs, screenshots, hashes) will be anonymized in reports and securely deleted after final delivery.
- Tester will follow ethical hacking principles: no harm, full disclosure of findings.
- Any critical vulnerability discovered will be reported immediately to approvers (within 1 hour).

### 7. Communication and Reporting
- **Progress Updates:** Daily email summary to Jim Allan (cc: XXXX XXXX) – high-level only, no raw sensitive data.
- **Incident Response:** If disruption or anomaly occurs: Pause testing → Notify emergency contact → Document → Await guidance.
- **Final Report Format:**
  - Executive Summary
  - Scope & Methodology
  - Findings Table (ID, Description, Severity, CVE if applicable, Impact, Recommendation)
  - Positive Observations
  - Remediation Prioritization
  - Appendices (anonymized evidence)

### 8. Risks and Assumptions
**Known Risks:** Scanning may trigger IDS alerts or brief performance impact (mitigated by off-hours and low-intensity settings).  
**Assumptions:** Provided VPN/access credentials remain valid; no major network changes during test window.

### 9. Signatures and Approval
I have read, understand, and agree to abide by the above Rules of Engagement.

**Tester:**  
XXXXX XXXXX _______________________________ Date: __________

**Approver 1:**  
XXXXX XXXXX _______________________________ Date: __________

**Approver 2:**  
XXXX XXXX _______________________________ Date: __________

**Amendments:** Any changes must be documented, agreed upon in writing, and appended to this document.

---
End of Document