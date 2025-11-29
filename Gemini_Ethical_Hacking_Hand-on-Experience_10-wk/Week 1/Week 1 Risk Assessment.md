# Week 1: Risk & Control Assessment Report - Debian 13 Lab Server

**1. Asset Categorization (NIST FIPS 199)**
| Component | Confidentiality Impact | Integrity Impact | Availability Impact | Overall Category | Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Debian 13 Server | Moderate | High | Moderate | **High** | *[Insert Rationale from Lab 1]* |

**2. Top 3 Identified Risks**
| Risk ID | Threat Source (MITRE TTP) | Vulnerability | Likelihood (Low/Med/High) | Impact (Low/Med/High) | Current Controls (NIST/ISO) | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| R-001 | T1078: Valid Accounts (Brute Force) | Open SSH Port 22 | Medium | High | AC-3 (SSH Key Auth) | Low |
| R-002 | T1486: Data Encrypted for Impact | Unencrypted Sensitive Config Files | High | Moderate | None (Control Gap) | **High** |
| R-003 | *[Choose one more threat from your review]* | *[Vulnerability/weakness]* | *[Estimate]* | *[Estimate]* | *[Existing control]* | *[Estimate]* |

**3. Mitigation Plan and Next Steps**
The highest residual risk is R-002 (unencrypted sensitive data).
**Action for Week 2:** Implement controls for data at rest protection (e.g., file system encryption) to satisfy NIST SC-28/ISO A.8.2.

# Week 1: Top 3 Identified Risks (Debian 13 Server)

| Risk ID | Threat Source (MITRE TTP) | Vulnerability | Likelihood (Low/Med/High) | Impact (Low/Med/High) | Current Controls (NIST/ISO) | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **R-001** | T1078: Valid Accounts (Brute Force/Password Spraying) | Open SSH Port 2222 (`0.0.0.0`) | Medium | High | AC-3 (SSH Key Auth), SC-7 (UFW Firewall) | **Low** |
| **R-002** | T1486: Data Encrypted for Impact (Ransomware/Data Theft) | Unencrypted Sensitive Config/User Files | High | Moderate | None (Control Gap) | **High** |
| **R-003** | T1560: Archive Collected Data (Local File Discovery) | Locally bound services (e.g., PostgreSQL Port 5432) storing data are exposed if the server is compromised (Privilege Escalation) | Medium | High | AC-6 (Principle of Least Privilege/Non-root user) | **Medium** |