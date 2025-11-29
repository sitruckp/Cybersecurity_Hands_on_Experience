# 🛡️ Server Hardening Log: Ubuntu Lab Server (Lynis Audit)

This log documents the process of addressing high-impact suggestions from a Lynis audit on a lab server, focusing on reducing the attack surface, improving package integrity, and enhancing forensic readiness.

[cite_start]**Initial Hardening Index Score:** 79 (with 0 warnings) [cite: 1]
[cite_start]**Goal:** Address high-priority suggestions aligning with Security+ and ethical hacking lab goals[cite: 3].

---

## 1. 🎯 Priority 1: Network Protocol Cleanup (NETW-3200)

[cite_start]This addresses the "least privilege" principle by disabling unused kernel modules, thus minimizing the attack surface[cite: 5, 10].

| Suggestion | Description |
| :--- | :--- |
| `NETW-3200` | [cite_start]Determine if protocols 'dccp', 'sctp', 'rds', and 'tipc' are really needed[cite: 7]. |

[cite_start]**Why it Matters:** Disabling these obscure protocols prevents exploitation of potential vulnerabilities in their module code[cite: 9].

### Step-by-Step Fix: Disabling Unused Kernel Modules

1.  [cite_start]**Create a Blacklist Configuration File**[cite: 12]:
    ```bash
    sudo nano /etc/modprobe.d/blacklist-unused-protocols.conf
    ```
2.  [cite_start]**Add the Blacklist Entries**[cite: 13]:
    ```
    # Disable unused protocols as suggested by Lynis (NETW-3200)
    blacklist dccp
    blacklist sctp
    blacklist rds
    blacklist tipc
    ```
3.  [cite_start]**Apply the Changes** (before the next reboot)[cite: 14]:
    ```bash
    sudo update-initramfs -u
    ```

---

## 2. 🎯 Priority 2: Improve Package Integrity Auditing (PKGS-7370, DEB-0810, DEB-0811)

[cite_start]This adds critical checks to the update process, aligning with supply chain security concepts[cite: 16].

| Suggestion | Description |
| :--- | :--- |
| `PKGS-7370` | [cite_start]Install `debsums` (to verify package files)[cite: 17]. |
| `DEB-0810` | [cite_start]Install `apt-listbugs` (to check for critical bugs before installing)[cite: 18]. |
| `DEB-0811` | [cite_start]Install `apt-listchanges` (to see significant changes before upgrading)[cite: 18]. |

### 🛠️ Error Encountered & Fix

[cite_start]**Initial Issue:** The command failed because `apt-listbugs` was not found in the default repositories (`E: Package 'apt-listbugs' has no installation candidate`)[cite: 32, 33]. [cite_start]Even after enabling the `universe` repository, the package was unavailable in the new Ubuntu Noble (24.04) release[cite: 49, 51].

[cite_start]**The Fix: Isolate the Installation**[cite: 54]:

1.  [cite_start]**Install Available Packages** (`debsums`, `apt-listchanges`)[cite: 57]:
    ```bash
    sudo apt update
    sudo apt install debsums apt-listchanges -y
    ```
2.  [cite_start]**Verification** (Confirms the tools are installed)[cite: 58]:
    ```bash
    sudo debsums -c
    ```

---

## 3. 🎯 Priority 3 (Partially Addressed): Insecure Remote Access Removal (INSE-8322)

[cite_start]This foundational security step involves removing the insecure Telnet service[cite: 20].

| Suggestion | Description |
| :--- | :--- |
| `INSE-8322` | [cite_start]Remove the `telnetd` server package and replace with SSH when possible[cite: 20]. |

### Step-by-Step Fix: Removing Telnet

> [cite_start]**CAUTION:** Only run this if you are connected via a secure service like SSH[cite: 21, 22].

1.  [cite_start]**Remove the Telnet Server Package**[cite: 23]:
    ```bash
    sudo apt purge telnetd -y
    ```
2.  [cite_start]**Verification** (Check if Telnet port 23 is still listening)[cite: 24]:
    ```bash
    sudo ss -tuln | grep 23
    ```
    *(No output indicates success)*

---

## 4. 🔒 Next Priority: Configure Auditd Ruleset (ACCT-9630)

[cite_start]This is a critical step for **forensic readiness** and setting up detective controls by configuring the Auditd daemon[cite: 64, 67].

| Suggestion | Description |
| :--- | :--- |
| `ACCT-9630` | [cite_start]Audit daemon is enabled with an empty ruleset[cite: 66]. |

### Step-by-Step Fix: Configuring Essential Rules

1.  [cite_start]**Create the Custom Rules File**[cite: 70]:
    ```bash
    sudo nano /etc/audit/rules.d/99-custom-hardening.rules
    ```
2.  [cite_start]**Add Essential Hardening Rules**[cite: 71, 72]:
    ```
    # === Essential Custom Auditd Rules for Lab Hardening ===

    # 1. Watch critical configuration files for modification (immutable rule)
    -w /etc/passwd -p wa -k identity_change
    -w /etc/group -p wa -k identity_change
    -w /etc/shadow -p wa -k identity_change
    -w /etc/sudoers -p wa -k config_change
    -w /etc/ssh/sshd_config -p wa -k config_change
    -w /etc/apt/sources.list -p wa -k package_repo_change

    # 2. Watch for changes to the audit configuration itself
    -w /etc/audit/ -p wa -k audit_config_change

    # 3. Monitor attempts to load or unload kernel modules (rootkit activity)
    -a always,exit -F arch=b64 -S init_module -S delete_module -k module_operation

    # 4. Enforce an immutable configuration (must be last rule)
    -e 2
    ```
    [cite_start]*Note: The `-e 2` rule enforces **Immutable Mode**, preventing an attacker from deleting the rules without a system reboot*[cite: 75].
3.  [cite_start]**Load the Rules**[cite: 77]:
    ```bash
    sudo augenrules --load
    ```
4.  [cite_start]**Verification** (Check loaded rules)[cite: 78]:
    ```bash
    sudo auditctl -l | grep identity_change
    ```

---

## ⏭️ Remaining High-Impact Suggestions

* [cite_start]**System Logging & Auditing:** Enable logging to an external logging host (`LOGG-2154`)[cite: 46, 65].
* [cite_start]**File System Integrity:** Dive into AIDE and switch its checksums to the more secure SHA512 (`FINT-4402`)[cite: 48, 61].
* [cite_start]**Kernel Hardening:** Tweak the remaining `sysctl` values (`KRNL-6000`)[cite: 28].
