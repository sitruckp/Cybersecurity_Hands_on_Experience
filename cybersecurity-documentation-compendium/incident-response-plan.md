# University Incident Response Plan (IRP)

**Version:** 1.0 (Audit & Insurance Ready)  
**Prepared by:** Kevin P. Curtis  
**Date:** April 2026  
**Classification:** Confidential – Internal Use Only

## 1. Purpose, Scope, and Authority

### 1.1 Purpose
This Incident Response Plan (IRP) establishes a structured and coordinated framework for detecting, analyzing, responding to, recovering from, and learning from cybersecurity incidents affecting the University.

**Objectives:**
- Minimize operational, financial, legal, and reputational impact
- Ensure timely, coordinated, and well-documented incident handling
- Preserve evidence for forensic investigation, legal proceedings, insurance claims, and regulatory reporting
- Support compliance with FERPA, GLBA, New Jersey breach notification laws, and other obligations
- Enable continuous improvement of the University’s cybersecurity posture

This IRP aligns with:
- NIST SP 800-61 Rev. 2 – Computer Security Incident Handling Guide
- NIST Cybersecurity Framework (CSF 2.0) – Respond and Recover Functions
- CIS Critical Security Control 17 – Incident Response Management

### 1.2 Scope
Applies to all University information systems, networks, applications, endpoints, research environments, and cloud services.

### 1.3 Authority
The Security Operations Center (SOC) is authorized to conduct detection, analysis, documentation, and recommend containment/remediation. Execution of disruptive actions remains with Server Operations or designated system owners (except in documented emergencies).

## 2. Roles and Responsibilities
A formal RACI matrix will be maintained as a supporting artifact.

### 2.1 Core Roles
- **SOC Lead / Incident Commander** — Overall coordination and escalation
- **SOC Analysts (Blue Team)** — Detection, triage, investigation, documentation
- **Server Operations** — Execution of containment, eradication, and recovery
- **Legal / Compliance / Privacy Officer** — Regulatory assessment and notifications
- **Executive Leadership** — Approval for major actions and external communications
- **Cybersecurity Training & Awareness Team** — Lessons learned and awareness updates

## 3. Incident Classification

### 3.1 Incident Categories (NIST / CISA Aligned)
Incidents are categorized and mapped to MITRE ATT&CK where applicable.

| Category                    | Description                          | Example ATT&CK Tactics          |
|-----------------------------|--------------------------------------|---------------------------------|
| Malware                     | Malicious software infection         | Execution, Persistence         |
| Credential Compromise       | Unauthorized account access          | Credential Access              |
| Phishing / Social Engineering | User deception attacks            | Initial Access                 |
| Ransomware                  | Encryption or extortion              | Impact                         |
| Data Exfiltration           | Unauthorized data transfer           | Exfiltration                   |
| Insider Threat              | Malicious or negligent insider       | Multiple                       |
| Web Application Attack      | Exploitation of web apps             | Initial Access                 |
| Denial of Service           | Service disruption                   | Impact                         |

### 3.2 Severity Levels and Escalation

| Severity  | Description                     | Typical Triggers                          | Required Notification                  |
|-----------|---------------------------------|-------------------------------------------|----------------------------------------|
| Low       | Minimal impact                  | Blocked phishing email                    | SOC                                    |
| Medium    | Limited compromise              | Single account misuse                     | SOC + Server Ops                       |
| High      | Significant impact              | Ransomware on servers, regulated data     | Leadership + Legal                     |
| Critical  | Widespread or regulated impact  | FERPA/GLBA breach, systemic compromise    | Executive + External                   |

## 4. Incident Response Lifecycle (NIST SP 800-61)

### Phase 1: Preparation
- Maintain contact lists, escalation matrix, and templates
- Ensure logging, SIEM/XDR, and tools are operational
- Conduct tabletop exercises
- Maintain procedures and playbooks

### Phase 2: Identification & Analysis
- Monitor alerts and reports
- Triage and document who/what/when/where/how
- Assign category and severity

### Phase 3: Containment
- Short-term: Isolate systems/accounts
- Long-term: Durable controls
- All actions logged and approved

### Phase 4: Eradication
- Remove malicious artifacts
- Disable compromised accounts
- Address root causes
- Validate eradication

### Phase 5: Recovery
- Restore from clean backups
- Monitor post-restoration
- Gradual return to production

### Phase 6: Post-Incident Activity
- After-action review (within 14 days for High/Critical)
- Document root cause, lessons learned
- Update policies, detections, and training

## 5. Communication and External Coordination
- Use secure channels only
- Legal/Compliance coordinates external notifications
- Notify CISA, law enforcement, and insurance carrier when appropriate

## 6. Evidence Handling, Legal Hold, and Forensics
- Follow chain-of-custody procedures
- Preserve originals; analyze copies
- Initiate legal holds when required

## 7. Metrics and Continuous Improvement
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Mean Time to Escalate (MTTE)
- Incident trends and control improvements

## 8. Plan Maintenance and Testing
- Reviewed annually or after Critical incidents
- Tested via tabletops, simulations, and Purple Team exercises

## 9. Approval
Recommended for Approval:  
Vice President _______________________ Date __________  
Server Operations Director _______________________ Date __________

## Appendix A – CIS Critical Security Control 17 Crosswalk
(Full detailed mapping table as in original document — every safeguard aligned to IRP sections.)