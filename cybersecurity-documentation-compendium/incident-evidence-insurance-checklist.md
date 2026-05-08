# Incident Evidence & Insurance Claims Checklist

**Confidential – Internal Use Only**  
**Prepared by:** Kevin P. Curtis  
**Date:** April 2026

## Executive Summary
This checklist ensures audit-ready, legally defensible, and forensically sound evidence handling during cybersecurity incidents. It supports cyber-insurance claims, regulatory compliance, and post-incident improvement.  

Aligned with:  
- NIST SP 800-61 Rev. 2  
- NIST SP 800-53 Rev. 5  
- CIS Critical Security Control 17  
- CISA Incident Response Guidance  
- MITRE ATT&CK Framework

## 1. Purpose and Scope
Applies to all High and Critical incidents, and any incident involving regulated data, ransomware, extortion, or potential insurance claims.

## 2. Evidence Collection and Preservation Checklist
- [ ] Open official incident record with unique ID
- [ ] Document incident category, severity, scope, and discovery time
- [ ] Identify affected systems, users, and data types (including regulated data)
- [ ] Preserve logs in read-only format where possible
- [ ] Verify time synchronization across all sources
- [ ] Capture forensic images of affected systems using approved tools
- [ ] Perform all analysis on copies only — never originals
- [ ] Replace tool-specific commands with placeholders (e.g., [Insert command here – approved EDR tool])

## 3. Chain of Custody Requirements
- [ ] Assign evidence custodian
- [ ] Label all evidence with incident ID, date, time, source, and handler
- [ ] Maintain detailed log of every access, transfer, or handling
- [ ] Restrict access to authorized personnel only
- [ ] Store evidence securely per University policy

## 4. Legal Hold and Retention
- [ ] Consult Legal/Compliance immediately to determine legal hold
- [ ] Suspend normal deletion/retention schedules
- [ ] Retain evidence according to legal, regulatory, and insurance requirements
- [ ] Do not alter or destroy evidence without written authorization

## 5. Cyber-Insurance Notification and Claims Support
- [ ] Review policy-specific notification deadlines
- [ ] Notify insurance carrier within required timeframe
- [ ] Preserve all communications with the carrier
- [ ] Document full incident timeline, scope, response actions, and financial impact
- [ ] Track remediation costs, downtime, and external expenses

## 6. Post-Incident Documentation and Audit Readiness
- [ ] Complete final incident report and executive summary
- [ ] Document root cause and contributing factors
- [ ] Record lessons learned and improvement actions
- [ ] Update playbooks, detections, and procedures
- [ ] Retain all documentation for audit, insurance, and regulatory review

## 7. Roles and Responsibilities
- **SOC** — Evidence identification, preservation, documentation
- **Server Operations** — Containment, eradication, recovery execution
- **Legal/Compliance** — Legal hold, breach determination, external notifications
- **Executive Leadership** — Risk acceptance and major decisions
- **Insurance Carrier** — Claims handling

This checklist, when followed, demonstrates due diligence for audits, insurance claims, and regulatory obligations.