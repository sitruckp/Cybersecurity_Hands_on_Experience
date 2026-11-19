## D482 – Secure Network Design (3 CUs)

**Assessment type:** Performance Assessment  
**Completion date:** [July 2026]

### Key competencies demonstrated
- Assessed business and technology needs along with network security vulnerabilities
- Designed secure physical and logical network architectures
- Recommended network security solutions aligned with industry best practices (segmentation, zero trust principles, defense in depth)
- Addressed regulatory and emerging threat considerations in a merged-network scenario

### Lab / practical connection
Network segmentation and least-privilege concepts from the course were applied in the home lab by using UFW to restrict Juice Shop (port 3000), DVWA (port 8080), and the Cowrie honeypot (port 2222) to local subnets only. Suricata was configured in promiscuous mode on the primary interface to monitor traffic to these isolated services, and Wazuh was used for centralized log collection—mirroring the role of Sentinel in the proposed merged network. This hands-on work reinforced the value of controlling the attack surface and generating detectable events.

Tools practiced
Network topology design and documentation
UFW (firewall rules for segmentation and local-only exposure)
Suricata (IDS monitoring points)
Wazuh (log aggregation and detection)
Docker isolation of vulnerable targets
Risk and compliance considerations (PCI-DSS, HIPAA-style controls)

### Artifacts
The proposed design for the Company A (financial) and Company B (medical software) merger replaces end-of-life network hardware with modern equivalents while introducing Zero Trust principles and Microsoft Azure services (including Sentinel for centralized logging and monitoring). The topology uses perimeter firewalls, segmented internal switches, encrypted remote access, and cloud connectivity to meet PCI-DSS and HIPAA requirements within the $50,000 first-year budget. Defense-in-depth and continuous verification replace the previous flat, poorly documented environments.

### Reflection
Designing the merged network highlighted how quickly end-of-life hardware and weak segmentation create risk. Applying similar isolation and monitoring principles in the home lab with UFW, Suricata, and Wazuh made the concepts concrete and showed how even a low-budget environment can demonstrate defense-in-depth.

---

*Note: These entries focus on competencies demonstrated and personal application rather than official course materials.*