## D487 – Secure Software Design (3 CUs)

**Assessment type:** Objective Assessment
**Completion date:** [October 2026]

### Key competencies demonstrated
- Applied secure software development lifecycle (SDLC) practices
- Performed threat modeling and risk assessment for applications
- Evaluated secure coding principles and testing strategies
- Integrated security into design and development processes (including Agile/DevSecOps concepts)

### Lab / practical connection
Secure software design concepts were reinforced by deliberately interacting with containerized vulnerable applications in the home lab. Juice Shop (port 3000) and DVWA (port 8080) were used to observe common insecure design patterns such as broken access control, injection flaws, and insufficient input validation. The Vulhub PHP CVE-2019-11043 environment provided a concrete example of how insecure configuration in a PHP-FPM + nginx stack can lead to remote code execution. These exercises illustrated how vulnerabilities often originate in design and configuration choices rather than solely in coding errors.

Tools practiced
OWASP Juice Shop (modern web application vulnerabilities)
DVWA (classic OWASP Top 10 practice)
Vulhub (CVE-2019-11043 PHP-FPM RCE environment)
Docker (isolation of vulnerable targets)
UFW (restricting access to practice environments)
Threat modeling mindset applied to observed application behavior

### Artifacts
Documented home-lab setup of Juice Shop, DVWA, and Vulhub with local-network-only exposure
Notes from generating and observing attack traffic against the vulnerable applications
Clean start/stop workflow for temporary vulnerable environments to limit resource use and risk

### Reflection
Practicing against intentionally vulnerable applications made the value of shifting security left tangible—many of the issues in Juice Shop and DVWA would have been cheaper and safer to address during design and requirements than after deployment. The lab also reinforced that even well-known vulnerabilities remain effective when applications are poorly designed or misconfigured.

---

*Note: These entries focus on competencies demonstrated and personal application rather than official course materials.*
