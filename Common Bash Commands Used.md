Common Bash Commands Used

Below are the common bash commands used in the lab, with explanations and Sec+ relevance.Package Management

Command: sudo apt update
What it does: Updates the local package index with the latest package information.
Why it’s used: Ensures latest package versions and security patches before installing software, reducing vulnerabilities (Sec+ objective 4.2).

Command: sudo apt install package-name -y
What it does: Installs a package (e.g., libpam-pwquality) and dependencies, with -y to auto-confirm.
Why it’s used: Installs security tools for hardening (e.g., PAM modules) (Sec+ objective 2.4).

Command: sudo apt purge package-name -y
What it does: Removes a package and its configuration files.
Why it’s used: Cleans up residual configs for [PKGS-7346], reducing attack surface (Sec+ objective 4.2).

Command: sudo apt autoremove -y
What it does: Removes unused dependencies.
Why it’s used: Minimizes unnecessary software, supporting system maintenance (Sec+ objective 4.2).

Command: sudo apt autoclean
What it does: Clears outdated package files from the cache.
Why it’s used: Frees disk space, ensuring a clean system (Sec+ objective 4.2).

Command: dpkg -l | grep '^rc'
What it does: Lists packages with rc status (removed but configs remain).
Why it’s used: Identifies residual configs for [PKGS-7346] cleanup (Sec+ objective 4.2).

Security Auditing
Command: sudo lynis audit system
What it does: Runs a Lynis security audit to identify vulnerabilities.
Why it’s used: Guides hardening with suggestions (e.g., [KRNL-5820]), supporting vulnerability scanning (Sec+ objective 4.1).

Command: sudo lynis audit system | grep TEST-ID
What it does: Filters Lynis output for a specific test ID (e.g., PKGS-7346).
Why it’s used: Verifies if a suggestion is resolved (Sec+ objective 4.1).

Command: sudo less /var/log/lynis.log
What it does: Views detailed Lynis audit logs.
Why it’s used: Troubleshoots unresolved suggestions (Sec+ objective 4.1).

System Configuration
Command: sudo nano /path/to/file
What it does: Opens a file (e.g., /etc/pam.d/common-password) in nano with root privileges.
Why it’s used: Edits configs for security settings (e.g., PAM, GRUB) (Sec+ objectives 2.4, 3.3).

Command: sudo nano -l -w /path/to/file
What it does: Opens a file in nano with line numbers (-l) and soft wrapping (-w).
Why it’s used: Improves readability for long configs (e.g., PAM) (Sec+ objective 2.4).

Command: cat /path/to/file | grep pattern
What it does: Displays file contents filtered for a pattern (e.g., cat /etc/security/limits.conf | grep core).
Why it’s used: Verifies config settings (e.g., core dumps) (Sec+ objective 3.1).

Command: sudo sysctl -p
What it does: Applies changes from /etc/sysctl.conf to the kernel.
Why it’s used: Enforces kernel security settings (e.g., fs.suid_dumpable=0) (Sec+ objective 3.1).

GRUB Boot Loader
Command: grub-mkpasswd-pbkdf2
What it does: Generates a PBKDF2 password hash for GRUB.
Why it’s used: Secures GRUB for [BOOT-5122] (Sec+ objective 3.3).

Command: sudo update-grub
What it does: Updates GRUB configuration.
Why it’s used: Applies GRUB password settings (Sec+ objective 3.3).

Command: sudo chmod 600 /etc/grub.d/*
What it does: Sets restrictive permissions on GRUB configs.
Why it’s used: Prevents unauthorized access to GRUB (Sec+ objective 3.3).

Command: sudo chown root:root /etc/grub.d/*
What it does: Ensures GRUB configs are owned by root.
Why it’s used: Reinforces GRUB security (Sec+ objective 2.4).

Systemd and Core Dumps
Command: sudo systemctl daemon-reload
What it does: Reloads systemd configuration.
Why it’s used: Applies DefaultLimitCORE=0 for [KRNL-5820] (Sec+ objective 3.1).

Command: ulimit -c
What it does: Displays core dump size limit.
Why it’s used: Verifies core dumps are disabled for [KRNL-5820] (Sec+ objective 3.1).

Command: sleep 100 & kill -SEGV $!; ls -l /var/crash
What it does: Triggers a test crash and checks for core dumps.
Why it’s used: Confirms no core dumps are created (Sec+ objective 3.1).

Troubleshooting
Command: sudo tail -f /var/log/auth.log
What it does: Monitors authentication logs.
Why it’s used: Debugs PAM or login issues (Sec+ objective 2.4).

Command: ls -l /path/to/file-or-dir
What it does: Lists permissions and ownership.
Why it’s used: Verifies secure configs (e.g., /etc/grub.d/*) (Sec+ objective 2.4).

Command: sudo journalctl -xe
What it does: Displays system logs, focusing on errors.
Why it’s used: Troubleshoots systemd issues (Sec+ objective 4.2).

Notes
Hardening followed Lynis suggestions, improving security for the LAMP web server.
Unrelated Lynis warnings (e.g., AIDE deprecated setting, speedtest-cli repository error) noted but not addressed.
Next steps include completing [PKGS-7346] and addressing suggestions like [FILE-6310] (separate partitions) or [BOOT-5264] (systemd hardening).

All changes verified with Lynis audits and manual checks, ensuring no impact on server functionality.