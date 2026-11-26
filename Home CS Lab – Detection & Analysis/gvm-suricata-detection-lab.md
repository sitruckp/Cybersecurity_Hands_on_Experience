# Home Lab Detection Engineering: From GVM Scan to Custom Suricata Alert

**Date:** November 26, 2026  
**Environment:** Home lab – labserver (Lenovo ThinkPad E520, Ubuntu 24.04.5 LTS)  
**Tools:** Greenbone Vulnerability Management (GVM / OpenVAS), Docker, Suricata 8.0.8, DVWA

## Executive Summary

A GVM vulnerability scan of the home lab identified Medium-severity findings on labserver (192.168.0.199), including cleartext transmission of login credentials on port 8080. Investigation confirmed the source as an intentional DVWA container. A custom Suricata rule was written and validated to detect POST requests to the application’s login page. The exercise demonstrates a complete detection-engineering workflow—from scan result to asset identification to working network alert—and highlights practical considerations such as rule-file placement and sensor interface visibility.

## Objective

Turn a vulnerability scan result into a working network detection. Specifically:

1. Analyze GVM scan reports of the home network.
2. Identify the service responsible for Medium-severity findings on port 8080.
3. Write and validate a custom Suricata rule that alerts on cleartext login attempts to that service.

## GVM Scan Summary

Two scans were performed:

- **Ethernet subnet** (192.168.0.0/xx)
- **Wi-Fi subnet** (192.168.1.0/xx)

No Critical or High findings were present after filtering (QoD ≥ 70). The most relevant Medium findings involved host **192.168.0.199** (labserver):

- Cleartext transmission of sensitive information (login form) on port 8080
- Missing `HttpOnly` cookie attribute
- Missing `Secure` cookie attribute
- Weak SSH MAC algorithms on port 2222
- TCP timestamps information disclosure (Low)

The same pattern appeared on the Wi-Fi address previously associated with the host (192.168.1.184).

## Asset Identification

On labserver the following commands identified the service:

```bash
sudo ss -tlnp | grep 8080
sudo docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Ports}}\t{{.Image}}"
```

**Result:**

- Container name: `dvwa`
- Image: `vulnerables/web-dvwa`
- Port mapping: `0.0.0.0:8080 → 80/tcp`
- Web server: Apache/2.4.25 (Debian)

This confirmed an intentional vulnerable application (DVWA) running in Docker. Other containers present included the Wazuh single-node stack, Juice Shop, syslog-ng, and a Tor proxy.

## Detection Development

A custom Suricata rule was created to detect POST requests to the DVWA login page.

### Final working rule

**File:** `/var/lib/suricata/rules/lab-cleartext.rules`

```suricata
alert http any any -> any 8080 (msg:"LAB - Test POST to login.php"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/login.php"; classtype:web-application-attack; sid:1000002; rev:2;)
```

### Key troubleshooting steps

1. **Rule path** – Suricata expected rules under `/var/lib/suricata/rules/`. The file was initially placed in `/etc/suricata/rules/` and had to be copied to the correct location with proper ownership (`suricata:suricata`).

2. **Traffic visibility** – Tests against `127.0.0.1` produced no alerts because Suricata was configured to watch only `enp2s0` (Ethernet). Traffic to the loopback interface is not visible to the sensor. Successful tests were performed from a second host (Kali at 192.168.0.107) targeting `http://192.168.0.199:8080/login.php`.

3. **Rule tuning** – An initial stricter rule that also matched `password=` in the request body did not fire. The simpler URI + method rule matched reliably and was retained.

### Validation

From Kali:

```bash
curl -s -X POST http://192.168.0.199:8080/login.php \
  -d "username=admin&password=password&Login=Login" -o /dev/null
```

**Alert example from `/var/log/suricata/fast.log`:**

```
11/26/2026-13:22:56.908820  [**] [1:1000002:2] LAB - Test POST to login.php [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.0.107:35726 -> 192.168.0.199:8080
```

Multiple matching alerts were generated, confirming the detection.

## Outcome

- Identified the intentional vulnerable target (DVWA container) responsible for the GVM Medium findings.
- Deployed a custom Suricata rule that reliably alerts on login attempts to that application.
- Documented the practical constraints of network sensor placement (interface selection and loopback traffic).

## Lessons Learned

- Vulnerability scan results are most useful when paired with asset identification and a corresponding detection.
- Rule file location and ownership matter; modern Suricata packages default to `/var/lib/suricata/rules/`.
- Network detections only work on traffic the sensor can see. Always test from a remote host when the sensor is bound to a physical interface.
- Starting with a simpler rule and adding conditions later is an effective way to debug matching issues.

## Next Steps (Optional)

- Forward the Suricata alert into the existing Wazuh manager so it appears in the Wazuh dashboard.
- Suppress noisy “Ethertype unknown” alerts (SID 2200121) to improve log readability.
- Extend coverage with additional rules for other intentional lab targets (e.g., Juice Shop on port 3000).

---

*This exercise demonstrates a complete detection-engineering loop suitable for a cybersecurity portfolio: scan → identify → detect → validate.*
