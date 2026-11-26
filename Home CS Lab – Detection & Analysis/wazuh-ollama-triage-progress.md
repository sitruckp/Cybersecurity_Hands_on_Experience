# Wazuh Monitoring Review and Ollama Triage Experiments

**Date:** 2026-11-25 to 2026-11-26  
**Lab:** Home cybersecurity lab (labserver – ThinkPad E520, Ubuntu 24.04)  
**Purpose:** Document understanding of Wazuh monitoring, establish a normal baseline, and evaluate local LLM (Ollama) for alert triage.

## Goals
- Understand what Wazuh is currently monitoring across agents.
- Create a reusable “normal baseline” note for future AI-assisted analysis.
- Test feeding Wazuh alerts into a local Ollama model for triage.
- Keep everything suitable for portfolio documentation.

## Agents and Monitoring in Scope
| Agent ID | Name              | OS                     | Key Activity Observed          |
|----------|-------------------|------------------------|--------------------------------|
| 002      | Kali              | Kali GNU/Linux 2026.3 | Morning dpkg/update spikes    |
| 003      | NUCBOX_M5Ultra    | Windows 11 Pro        | Low volume                    |
| 004      | UbuntuHPLapTop    | Ubuntu 26.04.1 LTS    | Low package activity          |
| 008      | Acer-Windows      | Windows 11 Home       | High FIM/registry noise       |
| 009      | Gaming_PC         | Windows 11 Home       | High FIM/registry noise       |
| 010      | Win10-PC          | Windows 10 Pro        | Highest overall volume        |
| 012      | labserver2        | Ubuntu 24.04.5 LTS    | Package updates, admin changes|

**Active Wazuh modules:** File Integrity Monitoring (syscheck/FIM), Security Configuration Assessment (SCA/CIS), log-based threat hunting, MITRE ATT&CK mapping, and limited malware detection.

**Wazuh deployment:** Docker single-node on labserver  
- Alerts log: `/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json`

## Key Findings
- **Overall (24h window):** ~6,070 alerts, 0 Level 12+, low authentication failures.
- **Dominant noise:** Windows registry FIM (syscheck add/delete/modify) and Linux dpkg/config_changed events.
- **Kali morning spike:** Confirmed as user’s normal startup script (apt update/upgrade + GVM signature update).
- **labserver2 ~06:02 activity:** Confirmed normal unattended-upgrades / apt package activity (half-configured → installed sequence is expected).
- **CIS/SCA results:** Many expected failures (password policy on Windows, mount options/permissions on Ubuntu). These are configuration gaps, not active incidents.

## Normal Baseline Note (for future prompts)
```
EXPECTED (summarize only):
- Kali (002): morning dpkg/config_changed/syslog spikes from apt update/upgrade + GVM signature script.
- UbuntuHPLapTop (004): similar apt update/upgrade activity, no GVM.
- labserver2 (012): early-morning dpkg/half-configured + installed alerts = normal unattended-upgrades; Suricata rule updates every Sunday; normal admin changes to shadow/group/UFW.
- All Windows agents: high volume of registry syscheck add/delete/modify events.
- No Level 12+ alerts and low auth-failure counts are normal.
```

## Ollama Experiments
- Confirmed native Ollama service running on labserver with `llama3.2:1b` and `llama3.2:3b`.
- Cleaned alert extracts (selected fields, level ≥ 7) and tested structured prompts.
- **Result:** Small local models produced readable summaries of package activity but failed to reliably follow structured “baseline vs anomalous” instructions or avoid mild hallucination.
- **Lesson:** Current small models are useful for simple one-shot questions but not yet reliable for bulk structured triage of raw Wazuh alerts.

## Next Directions
1. Update and maintain the baseline note as new normal routines are identified.
2. Continue manual or dashboard-based review for high-level awareness.
3. Explore alternative triage approaches (different model size/prompt style, agent-specific extracts, or other lightweight tools).
4. Document additional lab components (Suricata, etc.) as they mature.
5. Revisit local LLM triage once more capable small models or better prompt/context techniques are available.

## Portfolio Notes
- Demonstrates practical blue-team skills: log source identification, baseline establishment, noise reduction, and critical evaluation of AI-assisted analysis.
- Shows resource-aware experimentation on constrained hardware (12 GB RAM).
- All work performed with open-source tools in a documented home lab.

---
*End of session summary – ready for portfolio inclusion.*
