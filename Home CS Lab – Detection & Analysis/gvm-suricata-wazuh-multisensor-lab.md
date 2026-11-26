# Home Lab Detection Engineering: GVM Scan to Multi-Sensor Wazuh Collection

**Date:** November 26, 2026  
**Environment:** Home lab – labserver (Lenovo ThinkPad E520) and labserver2 (secondary sensor), Ubuntu 24.04.5 LTS  
**Tools:** Greenbone Vulnerability Management (GVM / OpenVAS), Docker, Suricata 8.0.8, Wazuh 4.14.9, DVWA

## Executive Summary

A GVM vulnerability scan of the home lab identified Medium-severity findings on labserver (192.168.0.199), including cleartext transmission of login credentials on port 8080. Investigation confirmed the source as an intentional DVWA container. Custom Suricata rules were written and validated on both labserver and labserver2. Suricata alerts were ingested into the central Wazuh manager (direct file monitoring on labserver, Wazuh agent on labserver2). Log rotation was configured on both sensors to prevent disk exhaustion. The exercise demonstrates a complete detection-engineering and multi-sensor collection workflow suitable for a cybersecurity portfolio.

## Objective

1. Analyze GVM scan reports and identify the service behind the Medium findings on port 8080.
2. Write and validate custom Suricata rules for the intentional vulnerable application.
3. Ingest Suricata alerts into Wazuh from both sensors.
4. Implement log rotation so the sensors remain operational.

## GVM Scan Summary

Two scans were performed (Ethernet 192.168.0.0/xx and Wi-Fi 192.168.1.0/xx). No Critical or High findings remained after filtering (QoD ≥ 70). The most relevant Medium findings on **192.168.0.199** (labserver) were:

- Cleartext transmission of sensitive information (login form) on port 8080
- Missing `HttpOnly` and `Secure` cookie attributes
- Weak SSH MAC algorithms on port 2222
- TCP timestamps information disclosure (Low)

## Asset Identification

Commands run on labserver:

```bash
sudo ss -tlnp | grep 8080
sudo docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Ports}}\t{{.Image}}"
```

**Result:**

- Container: `dvwa`
- Image: `vulnerables/web-dvwa`
- Mapping: `0.0.0.0:8080 → 80/tcp`
- Server: Apache/2.4.25 (Debian)

This confirmed an intentional vulnerable application. Other containers included the Wazuh single-node stack, Juice Shop, syslog-ng, and a Tor proxy.

## Suricata Detection Rules

### labserver rule (SID 1000002)

**File:** `/var/lib/suricata/rules/lab-cleartext.rules`

```suricata
alert http any any -> any 8080 (msg:"LAB - Test POST to login.php"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/login.php"; classtype:web-application-attack; sid:1000002; rev:2;)
```

### labserver2 rule (SID 1000003)

```suricata
alert http any any -> any any (msg:"LAB - Test HTTP POST"; flow:to_server,established; http.method; content:"POST"; classtype:web-application-attack; sid:1000003; rev:1;)
```

### Key troubleshooting

- Rules must live in `/var/lib/suricata/rules/` with correct ownership.
- Loopback traffic is invisible; tests must target the real interface IP.
- A stricter body match (`password=`) did not fire; the simpler method + URI rule was retained.
- Ethertype unknown noise (SID 2200121) was suppressed via `/etc/suricata/threshold.config`.

### Validation

Remote POST requests from Kali (192.168.0.107) produced matching alerts in `fast.log` and `eve.json` on both sensors.

## Wazuh Integration

### labserver (direct file monitor)

- Added read-only bind mount of `/var/log/suricata` into the Wazuh manager container.
- Added `<localfile>` block with `log_format` json pointing at `eve.json`.
- Raised JSON decoder limits in `local_internal_options.conf` to handle Suricata’s nested events.
- Alerts appear in the manager’s `alerts.json` with groups `["ids","suricata"]`.

### labserver2 (Wazuh agent)

- Existing Wazuh agent (pointed at 192.168.0.199) was configured with the same `<localfile>` entry.
- Suricata alerts (including SID 1000003) are forwarded and appear in the central `alerts.json` with `agent.name: labserver2`.

## Log Rotation

Both sensors received `/etc/logrotate.d/suricata` configurations:

- Daily rotation, 7 retained copies, compress, maxsize 500M.
- `su` directive used to satisfy permissions (`root suricata` on labserver, `root root` on labserver2).
- Post-rotate HUP so Suricata reopens log files.

This prevents the multi-gigabyte `eve.json` files from filling the disks.

## Outcome

- Identified the intentional DVWA target responsible for the GVM Medium findings.
- Deployed and validated custom Suricata rules on two sensors.
- Ingested alerts from both sensors into a central Wazuh manager.
- Implemented log rotation to keep the sensors operational.
- Documented practical issues (rule paths, interface visibility, JSON decoder limits, logrotate permissions).

## Lessons Learned

- Scan results become actionable only after asset identification and a corresponding detection.
- Network sensors only see traffic on the interfaces they monitor; always test from a remote host.
- SIEM JSON parsers often need limit increases for rich IDS event formats.
- Consistent log rotation and multi-sensor collection are essential for a sustainable detection lab.

## Architecture Summary

```
[Kali / other hosts]
        |
        v
[labserver Suricata] ----eve.json----> [Wazuh manager (Docker)]
        ^                                      ^
        |                                      |
[labserver2 Suricata] --Wazuh agent----------->+
```

Both sensors rotate their own logs. All Suricata alerts are searchable in the single Wazuh dashboard.

---

*This exercise demonstrates a complete detection-engineering and multi-sensor collection loop: scan → identify → detect → centralize → sustain.*
