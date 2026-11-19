## D486 – Governance, Risk, and Compliance (2 CUs)

**Assessment type:** Objective Assessment  
**Completion date:** [August 2026]

### Key competencies demonstrated
- Applied governance frameworks and risk management processes
- Evaluated compliance requirements and control implementation
- Assessed organizational risk and recommended mitigation strategies
- Aligned security controls with business objectives and regulatory expectations

### Lab / practical connection
GRC concepts were applied in the home lab by restricting Juice Shop, DVWA, and Cowrie to local subnets only with UFW, enforcing least privilege on Docker containers and host services, and maintaining clear visibility into exposed ports. This mirrors the emphasis on least privilege (AC-6), continuous monitoring (CA-7), and documented risk response (RA-7) used in the XXXXXXX Medical Center remediation. The lab demonstrates practical control of the attack surface without exposing vulnerable targets to the broader network.

Tools / frameworks referenced
NIST SP 800-53 Rev. 5 (AC-6, CA-5, CA-7, RA-3, RA-7)
NIST Risk Management Framework (SP 800-37)
PCI DSS
UFW (network access controls and least-privilege exposure)
Docker (container isolation and privilege reduction)
Suricata / Wazuh (monitoring and logging visibility)

### Artifacts
The Security System Evaluation and Remediation for XXXXXX Medical Center identified gaps against NIST SP 800-53 Rev. 5 and FISMA requirements, focusing on five priority controls (AC-6 Least Privilege, CA-5 POA&M, CA-7 Continuous Monitoring, RA-3 Risk Assessment, and RA-7 Risk Response). Remediation plans were developed for each control rather than risk acceptance, and a PCI DSS–compliant policy was written for the planned point-of-sale environment. The approach emphasized documented risk decisions, least privilege, continuous monitoring, and formal tracking of weaknesses.

### Reflection
GRC work reinforced that controls only reduce risk when they are documented, owned, and monitored over time. Applying least privilege and local-only exposure in the home lab showed how the same principles that protect a federally funded medical environment also keep a personal detection lab safe and auditable.

---

*Note: These entries focus on competencies demonstrated and personal application rather than official course materials.*