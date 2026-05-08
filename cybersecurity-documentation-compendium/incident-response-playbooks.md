# Incident Response Framework — Playbooks

**Classification:** Confidential — Internal Use Only  
**Prepared by:** Kevin P. Curtis  
**Date:** April 2026

## Overview & Framework Alignment
Standardized playbooks aligned to NIST SP 800-61 Rev. 2, NIST CSF 2.0, CIS Critical Security Control 17, CISA guidance, MITRE ATT&CK, and OWASP.  

**Authority Model:** SOC recommends actions; Server Operations executes disruptive controls.

### Playbook 1: Ransomware and/or Data Exfiltration
**Severity:** High to Critical  
**Triggers:** Ransom notes, encryption activity, outbound data spikes, SIEM alerts  
**MITRE ATT&CK:** Impact (TA0040), Exfiltration (TA0010), Lateral Movement (TA0008)  

**Checklist:**
- Detection & Analysis
- Containment (isolation, credential resets, indicator blocking)
- Evidence Preservation (logs, forensic images)
- Eradication
- Recovery with heightened monitoring
- Notifications (Legal, Executive, Insurance, Regulators)

### Playbook 2: Phishing / Business Email Compromise (BEC)
**Triggers:** User reports, mail gateway alerts, anomalous sign-ins  
**MITRE ATT&CK:** Initial Access (TA0001), Credential Access (TA0006)  

**Checklist:**
- Validate email and scope impact
- Account lockdown / password reset / MFA re-enrollment
- Block sender infrastructure
- User and leadership communications

### Playbook 3: Compromised User Account
**Triggers:** Impossible travel, failed logins, anomalous access  
**MITRE ATT&CK:** Credential Access (TA0006), Persistence (TA0003)  

**Checklist:**
- Account suspension and session revocation
- Credential reset with forced MFA
- Investigation and monitoring hold period
- User notification template

### Playbook 4: Confirmed Data Breach / Regulated Data Exposure
**Severity:** Critical  
**Triggers:** Evidence of exfiltration or third-party notification  
**MITRE ATT&CK:** Exfiltration (TA0010)  

**Checklist:**
- Activate CSIRT
- Preserve evidence and determine scope
- Executive/Legal notification
- Regulatory and individual notifications as required
- Recovery and post-incident review

## Appendix B – CIS Critical Security Control 17 Mapping
(Full crosswalk table preserved from original — every safeguard mapped to playbooks.)

## Appendix C – Executive Summary of Playbooks
These playbooks provide a standardized, defensible approach to handling cyber incidents while minimizing operational risk and supporting compliance, insurance, and audit requirements.