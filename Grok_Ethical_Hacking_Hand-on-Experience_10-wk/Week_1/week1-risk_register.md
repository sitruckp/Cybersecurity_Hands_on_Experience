# Week 1: Security and Risk Management - Risk Register
**Asset**: Debian 13 Server (lab-server)  
**Scan Date**: 2025-11-13  
**Tool**: Lynis v3.1.4 | **Hardening Index**: 86/100  
**Analyst**: kevin

| Risk | Likelihood (1-5) | Impact (1-5) | Score | Mitigation | Status |
|------|------------------|--------------|-------|------------|--------|
| Lynis version outdated | 2 | 2 | 4 | `sudo lynis update release` | Done |
| No PAM tmpdir control | 3 | 3 | 9 | `sudo apt install libpam-tmpdir -y` | Done |
| No critical bug checks before install | 3 | 3 | 9 | `sudo apt install apt-listbugs -y` | Done |
| (Simulated) Unencrypted /tmp | 4 | 4 | 16 | `sudo mount -o remount,exec,noatime /tmp` + fstab | Pending |
| Lynis version outdated | 2 | 2 | 4 | Use `apt` (current) | Done |
| No critical bug checks | 3 | 3 | 9 | `sudo apt install apt-listbugs -y` | Done |
| (Simulated) Unencrypted /tmp | 4 | 4 | 16 | `sudo mount -o remount,noexec,nodev,nosuid /tmp` | Pending |



**Compliance Mapping (NIST SP 800-53)**:
- **SI-2**: Flaw Remediation → apt-listbugs
- **SC-28**: Protection of Information at Rest → libpam-tmpdir
- **CM-6**: Configuration Settings → Lynis update 
- **CM-6**: Configuration Settings -> Lynis audit

