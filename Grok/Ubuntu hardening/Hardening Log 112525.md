# Hardening Log and Common Bash Commands - Ubuntu 24.04 LTS Server (2025-11-25)

This document logs the server hardening activities performed on November 25, 2025, for a cybersecurity lab on an Ubuntu 24.04 LTS server hosting a LAMP stack. It also lists common bash commands used in the lab, with explanations and ties to CompTIA Security+ (Sec+ SY0-701) principles. The goal is to achieve a Lynis hardening index of 80+ by addressing audit suggestions, enhancing access control, data protection, and vulnerability management.

## Environment
- **OS**: Ubuntu Server 24.04 LTS
- **Setup**: LAMP stack (Apache, MySQL, PHP), static IP (192.168.1.XXX/24), OpenSSH (port 2222), UFW, Fail2Ban, AppArmor
- **Lynis Status (Start)**: Hardening index 77, 32 suggestions, no warnings
- **Lynis Status (End)**: Hardening index 79, 28 suggestions, no warnings
- **User**: kevin

## Hardening Steps Completed

### 1. Install PAM Module for Password Strength Testing [AUTH-9262]
- **Objective**: Enforce strong password policies using `libpam-pwquality` to address Lynis suggestion [AUTH-9262], enhancing access controls (Sec+ objective 2.4).

- **Actions**:
  - Installed `libpam-pwquality`.
  - Configured `/etc/security/pwquality.conf` for minimum length (12), requiring digits, uppercase, lowercase, and special characters.
  - Edited `/etc/pam.d/common-password` to add `password requisite pam_pwquality.so retry=3` before `pam_unix.so`.
  - Updated `pam_unix.so` to use `yescrypt` (from `sha512`) for stronger hashing.
  - Commands:
    ```bash
    sudo apt update
    sudo apt install libpam-pwquality -y
    sudo nano /etc/security/pwquality.conf
    sudo nano -l -w /etc/pam.d/common-password
    sudo passwd kevin
    sudo lynis audit system | grep AUTH-9262