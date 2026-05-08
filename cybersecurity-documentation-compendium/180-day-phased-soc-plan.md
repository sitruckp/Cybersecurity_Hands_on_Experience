# 180-Day Phased Plan to Build a Sustainable Cybersecurity Blue Team (SOC)

**Prepared by:** Kevin P. Curtis  
**Date:** April 2026

## Executive Summary

This proposal outlines a measured, low-risk 180-day roadmap to establish a sustainable in-house Security Operations Center (SOC) capability at the University. The plan prioritizes visibility, detection, and operational stability before introducing automation or adversarial testing, aligning with best practices in higher-education environments.

The approach emphasizes:
- Blue Team first development
- Observe-only operations during early phases
- Sequential maturity, layering capabilities thoughtfully
- Controlled validation through Purple Teaming rather than early Red Team exercises

By Day 180, the University will have a mature defensive posture supported by centralized monitoring, tuned detections, limited automation, and proven response processes—without introducing unnecessary operational risk.

This plan aligns with the NIST Cybersecurity Framework (Identify → Protect → Detect → Respond) and can begin with a small pilot on non-critical systems. Costs remain minimal using open-source options, with clearly defined commercial alternatives if desired.

## Guiding Principles (Applies to All Phases)

- **Blue Team First**  
  Detection and response capabilities must be established before adversarial testing.
- **Observe-First, Then Automate**  
  No automated blocking or enforcement until alert quality and volume are proven stable.
- **Sequential Maturity**  
  SIEM and endpoint visibility precede network IDS; IPS is introduced last and only after validation.
- **Operational Safety**  
  Academic continuity and system uptime take precedence over aggressive security controls.
- **Framework Alignment**  
  Activities map directly to the NIST Cybersecurity Framework.

## Integrated SOC Maturity Roadmap

### Phase 1: Days 1–30 — Identify & Architecture Foundations
**Goal:** Establish governance, logging strategy, and monitoring architecture with minimal operational risk.

**Key Activities**
- Conduct asset inventory as an ongoing background task (servers, endpoints, critical applications).
- Draft SOC charter, roles, escalation procedures, and reporting cadence.
- Define logging standards (log sources, retention, and prioritization).
- Select tooling path:  
  - Open-source: Wazuh integrated with ELK Stack  
  - Commercial: Microsoft Sentinel with Defender (or equivalent)

**Controls**
- No automation
- No blocking
- No network traffic inspection

**Milestone**
- ~80% asset visibility achieved
- SIEM/XDR architecture and platform decision documented

### Phase 2: Days 31–60 — SIEM & XDR Initial Deployment (Observe-Only)
**Goal:** Establish centralized visibility across endpoints and servers.

**Key Activities**
- Deploy SIEM core and ingest authentication, server, endpoint, and critical application logs.
- Deploy XDR agents on 5–10 non-critical systems.
- Enable log correlation, file-integrity monitoring, and vulnerability detection.
- Disable all active response and enforcement capabilities.

**Controls**
- Observe-only mode
- Manual alert review

**Success Criteria**
- Reliable log ingestion and searchability
- Alert volume reduced to a manageable baseline (<10–15/day after tuning)

### Phase 3: Days 61–90 — SIEM Tuning & Operationalization
**Goal:** Improve signal quality and formalize operational workflows.

**Key Activities**
- Expand log sources and endpoint coverage.
- Tune correlation rules and detections based on real activity.
- Formalize manual triage workflows.
- Train IT/security staff on dashboards, investigations, and reporting.

**Optional (Accelerated Track Only)**
- Limited, non-disruptive automation (e.g., alert tagging or notifications) after stability is proven.

**Explicit Exclusions**
- No network blocking
- No IPS enforcement

**Milestone**
- Stable SIEM-driven monitoring
- Weekly operational reporting established

### Phase 4: Days 91–120 — Network IDS Deployment (Detect-Only)
**Goal:** Add network-level visibility without affecting traffic.

**Key Activities**
- Deploy IDS sensors (Suricata or Zeek) via SPAN/TAP ports.
- Focus on metadata-first inspection and anomaly detection.
- Integrate IDS alerts into SIEM for correlation.

**Controls**
- Detection only (no prevention)

**Milestone**
- Correlated endpoint and network visibility with manageable alert volume

### Phase 5: Days 121–150 — Controlled Automation & IPS Readiness
**Goal:** Reduce analyst workload while preparing for limited prevention.

**Key Activities**
- Enable light automation (alert enrichment, case creation, analyst notification).
- Identify a non-critical test segment suitable for IPS evaluation.
- Convert IDS rules for IPS readiness without enabling blocking.
- Conduct tabletop exercises using real alerts.

**Gate Conditions**
- Predictable alert behavior
- False positives understood
- Manual response proven reliable

**Milestone**
- Organization approves limited IPS testing scope

### Phase 6: Days 151–180 — IPS Pilot & Purple Team Validation
**Goal:** Validate detection and prevention capabilities safely.

**Key Activities**
- Enable IPS on approved test segment only using high-confidence signatures.
- Conduct Purple Team exercises to validate detection, response, and prevention jointly.
- Produce after-action report and prioritized improvement roadmap.
- Finalize documentation, ownership, and metrics.

**Explicit Exclusions**
- No campus-wide IPS enforcement
- No full adversarial Red Team operations

**Milestone**
- Sustainable SOC operation with validated prevention capability

## Tooling Options

**Open-Source (Primary Recommendation)**
- SIEM/XDR: Wazuh + ELK
- IDS/IPS: Suricata, Zeek
- Automation: Built-in Wazuh capabilities (SOAR tools deferred)

**Commercial Alternatives**
- Microsoft Sentinel + Defender
- Rapid7 InsightIDR
- CrowdStrike Falcon
- Splunk (with integrated playbooks)

## Benefits to the University
- Increased visibility across endpoints, servers, and networks
- Faster detection and response to security events
- Reduced operational risk through phased, observe-first deployment
- Measurable progress suitable for leadership and accreditation reporting
- Scalable foundation for future maturity

## Conclusion
This 180-day plan provides a stable, defensible, and sustainable path for improving the University’s cybersecurity posture while minimizing disruption. It balances security improvement with operational reality and positions the University for long-term resilience.