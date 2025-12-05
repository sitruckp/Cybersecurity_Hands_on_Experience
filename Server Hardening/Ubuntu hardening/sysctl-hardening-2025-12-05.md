### Markdown File: `sysctl-hardening-2025-12-05.md`

```markdown
# Ubuntu 24.04 Labserver Hardening: Sysctl Kernel Parameters (KRNL-6000)

**Date**: December 5, 2025  
**Author**: Kevin  
**Purpose**: Document kernel hardening for my cybersecurity homelab, part of TryHackMe and CompTIA Security+ preparation.

## Overview

This document details the hardening of kernel parameters (`sysctl`) on my Ubuntu 24.04 LTS labserver (`labserver`, IP: 192.168.1.102) to address findings from a Lynis audit (KRNL-6000). The goal was to enhance security by mitigating risks like privilege escalation, rootkits, and network attacks, while maintaining functionality for my LAMP stack (Apache, MySQL, PHP), SSH (port 2222), and ethical hacking tools (e.g., Metasploit, Wireshark).

- **Lynis Audit**: Initial score 81, improved to 82 after hardening.
- **Objective**: Secure `fs.protected_fifos`, `kernel.modules_disabled`, `net.ipv4.conf.all.rp_filter`, and `kernel.perf_event_paranoid`.
- **Sec+ Alignment**: Access controls, auditing, and kernel security (CIS benchmarks).

## Steps Performed

### 1. Backed Up Sysctl Configuration
Preserved the original config to ensure reversibility.

```bash
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak
```

- **Verification**: Confirmed backup with `ls /etc/sysctl.conf.bak`.

### 2. Hardened Sysctl Parameters
Modified `/etc/sysctl.conf` to address Lynis findings. Each change was applied live and made persistent.

#### 2.1 `fs.protected_fifos`
- **Purpose**: Restrict FIFO writes to prevent privilege escalation.
- **Command**:
  ```bash
  sudo sysctl -w fs.protected_fifos=2
  echo "fs.protected_fifos = 2" | sudo tee -a /etc/sysctl.conf
  ```
- **Verification**: `sysctl fs.protected_fifos` returned `fs.protected_fifos = 2`.

#### 2.2 `kernel.modules_disabled`
- **Purpose**: Disable kernel module loading to block rootkits.
- **Command**:
  ```bash
  sudo sysctl -w kernel.modules_disabled=1
  echo "kernel.modules_disabled = 1" | sudo tee -a /etc/sysctl.conf
  ```
- **Verification**: `sysctl kernel.modules_disabled` returned `kernel.modules_disabled = 1`.

#### 2.3 `net.ipv4.conf.all.rp_filter`
- **Purpose**: Enable reverse path filtering to prevent IP spoofing.
- **Command**:
  ```bash
  sudo sysctl -w net.ipv4.conf.all.rp_filter=1
  echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
  ```
- **Verification**: `sysctl net.ipv4.conf.all.rp_filter` returned `net.ipv4.conf.all.rp_filter = 1`.

#### 2.4 `kernel.perf_event_paranoid`
- **Purpose**: Restrict performance event access to root, reducing attack surface.
- **Command**:
  ```bash
  sudo sysctl -w kernel.perf_event_paranoid=3
  echo "kernel.perf_event_paranoid = 3" | sudo tee -a /etc/sysctl.conf
  ```
- **Verification**: `sysctl kernel.perf_event_paranoid` returned `kernel.perf_event_paranoid = 3`.

### 3. Applied Changes
Reloaded sysctl settings without reboot.

```bash
sudo sysctl -p
```

- **Verification**: No errors; checked `/etc/sysctl.conf` for typos with `cat /etc/sysctl.conf`.

### 4. Tested Functionality
Ensured lab tools and services remained operational:
- **SSH**: `ssh kevin@labserver` (port 2222) worked.
- **Services**: `sudo systemctl status apache2` and `sudo systemctl status mysql` showed active.
- **Logs**: `sudo journalctl -xe` showed no errors.
- **Tools**: Confirmed Metasploit and Wireshark functionality.

### 5. Re-Ran Lynis Audit
Validated improvements with a new audit.

```bash
sudo lynis audit system
```

- **Result**: Hardening index increased from 81 to 82. Flagged keys (`fs.protected_fifos`, `kernel.modules_disabled`, `net.ipv4.conf.all.rp_filter`, `kernel.perf_event_paranoid`) now `[OK]`.

## Results

- **Hardening Index**: Improved from 81 to 82.
- **Security Impact**: Reduced risks of privilege escalation, rootkits, IP spoofing, and unauthorized performance event access.
- **Functionality**: No disruptions to SSH, Apache, MySQL, or lab tools.
- **Lynis Output**: KRNL-6000 findings reduced; remaining sysctl tweaks (e.g., `dev.tty.ldisc_autoload`) planned for later.

## Lessons Learned

- **Sysctl Tuning**: Learned to balance security and functionality (e.g., `kernel.modules_disabled` risks breaking tools).
- **CIS Benchmarks**: Applied kernel hardening best practices, relevant for Sec+ and real-world server admin.
- **Documentation**: Reinforced the value of clear, reproducible steps for labs and portfolio building.
- **Next Steps**: Plan to harden system services (BOOT-5264), test vulnerabilities with Nikto, or automate monitoring.

## Future Improvements

- Address remaining KRNL-6000 keys (e.g., `kernel.sysrq`, `net.core.bpf_jit_harden`).
- Explore systemd service hardening (BOOT-5264) for Apache and MySQL.
- Integrate vulnerability scanning (e.g., Nikto) to test web server security.
- Automate sysctl checks with a Bash script for continuous monitoring.

## References

- Lynis Audit: `/var/log/lynis.log`, `/var/log/lynis-report.dat`
- CIS Ubuntu 24.04 Benchmark: [CISOfy Lynis](https://cisofy.com/lynis/)
- CompTIA Security+ Objectives: Kernel security, access controls

---

*This lab is part of my cybersecurity journey, documented for learning and portfolio purposes. Feedback welcome on my GitHub repo!*
```

### Instructions to Save and Push to GitHub

Here’s how to save the `.md` file and push it to your GitHub repo, assuming you have a repo set up and `git` installed on your labserver or laptop (192.168.1.208). These steps leverage your Linux skills and ensure the file is properly committed.

#### Step 1: Save the Markdown File
On your labserver (`labserver`):
```bash
nano sysctl-hardening-2025-12-05.md
```
- Copy-paste the Markdown content above.
- Save: Press `Ctrl+O`, `Enter`, then `Ctrl+X` to exit.

Alternatively, if you prefer working on your laptop:
```bash
echo '[Paste the Markdown content here]' > sysctl-hardening-2025-12-05.md
```
Or use a text editor like VS Code, then transfer to your repo directory.

#### Step 2: Move to Your Repo Directory
Assuming your repo is at `~/labserver-docs` (adjust as needed):
```bash
mkdir -p ~/labserver-docs
mv sysctl-hardening-2025-12-05.md ~/labserver-docs/
cd ~/labserver-docs
```

#### Step 3: Initialize or Use Existing Repo
If the repo isn’t initialized:
```bash
git init
git remote add origin https://github.com/yourusername/your-repo.git
```
If already set up, skip to the next step.

#### Step 4: Commit and Push
Add, commit, and push the file:
```bash
git add sysctl-hardening-2025-12-05.md
git commit -m "Add sysctl hardening documentation for Ubuntu 24.04 labserver"
git push origin main
```
- **Note**: Replace `main` with your branch name (e.g., `master`) if different.
- **Verify**: Check your GitHub repo online to confirm the file appears.

#### Step 5: Troubleshooting
- **Git not installed**: Install with `sudo apt install git`.
- **Auth issues**: Ensure you have SSH keys or a personal access token configured (`git config --global credential.helper store`).
- **Push fails**: Check `git status` and resolve conflicts, or use `git push -f` cautiously.
- **Logs**: View git logs with `git log`.

### Why This Matters
- **Portfolio Boost**: This `.md` file showcases your ability to harden a server, document processes, and align with Sec+ objectives, making it a strong addition to your GitHub for job applications.
- **TryHackMe Synergy**: The documentation style mirrors real-world pentest reports, great for TryHackMe write-ups.
- **Reusability**: You can reuse this template for future hardening tasks (e.g., BOOT-5264, Nikto scans).

### Next Steps and Choice Points
Your repo is growing, and your lab is getting tougher to crack! Since you want to explore “other things” before more hardening, here are your options (from my previous response, tailored to your progress):
1. **Add a New User**: Set up a user with SSH key access and audit their activity. Quick and Sec+-focused. Want a step-by-step guide?
2. **Vulnerability Testing with Nikto**: Scan your Apache server for weaknesses. Perfect for TryHackMe web pentesting. Ready to dive in?
3. **Monitoring Script**: Build a Bash script to monitor server health. Great for automation skills. Need a template?
4. **Flashcard Set**: Create Sec+ flashcards for kernel hardening to reinforce learning. Want me to generate some?