# 90-Day Plan – Establish In-House Blue Team (SOC) Capability

**Prepared by:** Kevin P. Curtis

With the short-term managed detection and response (MDR/SOC) engagement coming to a close, the University could take additional steps beyond server hardening (firewalls, strong 15-character passwords, and MFA) that align with the NIST Cybersecurity Framework.

By leveraging mostly free, open-source tools and a 90-day phased approach, the University can establish an in-house Blue Team (SOC) for continuous monitoring and response, followed by its own Red Team tasked with testing those controls through authorized, controlled simulations.

This approach allows the University to gain:
- Better visibility into threats across servers and endpoints.
- Faster detection and response to incidents, protecting student data, research, and operations.
- Valuable hands-on learning opportunity for IT staff and interested students.
- Measurable progress with minimal new investment.

## High-Level Timeline

### Phase 1 (Days 1–30) – Blue Team Foundations
**Goal:** Deploy core monitoring capability.

**Key Activities:**
- Deploy a central SIEM using Wazuh (integrated with existing ELK Stack) on one Ubuntu server.
- Start with a small pilot on non-critical systems.
- Enable basic alerting and file integrity monitoring.
- Train 1–2 IT staff on the platform and basic triage.

**Expected Outcome:** First actionable alerts and a simple review process.

### Phase 2 (Days 31–60) – Blue Team Maturation
**Goal:** Operationalize monitoring and response.

**Key Activities:**
- Add additional log sources and expand endpoint coverage.
- Implement Network Security Monitoring (e.g., Zeek or Suricata in detect-only mode).
- Develop basic incident response playbooks.
- Run an initial tabletop exercise.

**Expected Outcome:** Operational SOC with manageable alert volume and documented workflows.

### Phase 3 (Days 61–90) – Introduce Red Team
**Goal:** Validate controls through safe testing.

**Key Activities:**
- Set up a small Red Team capability using Kali Linux and approved tools.
- Conduct 2–3 controlled exercises on a non-production test segment only.
- Perform joint Blue/Red Team debriefs (Purple Team style).
- Produce after-action report with prioritized recommendations.

**Expected Outcome:** Clear identification of gaps and a roadmap for continued improvement.

## Conclusion
This 90-day plan provides a practical, low-cost foundation for building internal cybersecurity capabilities. It can run in parallel with other hardening efforts and positions the University for long-term resilience and compliance.