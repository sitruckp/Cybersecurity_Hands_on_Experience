# Week 1: Reconnaissance and Network Discovery  
## Session 2: Passive vs Active Reconnaissance + Basic Host Discovery  
**Date:** February 6, 2026  
**Location:** Home Lab (State College, PA)  
**Objective:** Practice low-risk information gathering to identify live hosts on my isolated lab network. Focus on distinguishing passive and active techniques, and observe how different probes affect discovery results. All activities limited to my own 192.XXX.XXX.XXX/24 home LAN (treating it as controlled lab scope — no external or unauthorized targets).

### Key Concepts Reviewed
- **Passive reconnaissance**: Gathering info without sending packets to targets (e.g., Shodan, Google dorks, public records). Stealthy, low/no risk of detection.
- **Active reconnaissance**: Sending probes directly to targets (e.g., ping, TCP SYN). More informative but detectable/loggable.
- Ties to **NIST CSF Identify function** → Asset Management (ID.AM): You can't protect devices you don't know exist.

### Lab Setup
- Attacker: Kali Linux (192.XXX.XXX.XXX / 192.XXX.XXX.XXX observed)
- Targets: Ubuntu server (labserver.lan / 192.XXX.XXX.XXX), Desktop-Ubuntu24 (192.XXX.XXX.XXX), various home devices (router, Xbox, ecobee, etc.)
- Tools used: `ping`, `nmap`, Wireshark (on target system)

### Activities Completed

1. **Manual ping verification**  
   Confirmed reachability to known lab hosts:
   - `ping -c 1 192.XXX.XXX.XXX` → success (labserver)
   - `ping -c 1 192.XXX.XXX.XXX` → success (Desktop-Ubuntu24)

2. **Basic Nmap ping sweep (ICMP + default TCP fallback)**  
   Command:sudo nmap -sn 192.XXX.XXX.XXX/24

   Result: **16 hosts up**  
Saved output to file (not shown here for brevity).

3. **Enhanced Nmap ping sweep with extra TCP probes**  
Command: sudo nmap -sn -PE -PS22,80,443,3389,2222 192.XXX.XXX.XXX/24

Result: **17 hosts up**  
Observation: One additional host responded only to TCP SYN probes (likely blocks ICMP but has open/listening ports).

4. **Repeated basic ping sweep (later run)**  
Command: `sudo nmap -sn 192.XXX.XXX.XXX/24`  
Result: **20 hosts up**  
Observation: Network state changed (new devices appeared — common in home/DHCP environments).

5. **Wireshark capture & analysis of Nmap -sn sweep**  
- Captured on target system while running the basic ping sweep.  
- Key filters used:
  - `ip.src == <kali-ip>` → isolate scanner traffic
  - `icmp.type == 8 or icmp.type == 0` → Echo Request/Reply (ping)
  - `tcp and (tcp.flags.syn == 1 and tcp.flags.ack == 0)` → TCP SYN probes
- Findings:
  - Burst of ICMP Echo Requests to sequential IPs
  - Fewer Echo Replies → many devices ignore ICMP
  - TCP SYN to ports 80/443 observed as fallback
  - Helped explain why extra hosts appeared with -PS flags

### Key Takeaways
- Relying only on ICMP ping misses stealthy/hardened devices (IoT, firewalls).
- Combining ICMP + targeted TCP probes increases discovery completeness.
- Active recon creates visible packets — even light scans are detectable with monitoring.
- Relevance to university networks: Thousands of diverse devices (BYOD, smart classrooms, research servers) → incomplete discovery = blind spots in asset inventory.

### Reflection Questions Answered
1. Passive gives broad/external context with zero direct risk; active provides precise live-host data but generates logs/traffic.
2. Stealthy devices (e.g., those blocking ICMP) require multiple probe types — seen firsthand with the extra host(s).
3. Missing hosts during discovery means security controls (patching, monitoring) can't be applied → high risk in shared/academic environments.

### Next Session Plan
- Week 1 Session 3: Targeted reconnaissance — basic port scanning + service/version detection (`-sV`) on selected lab servers only (e.g., 192.XXX.XXX.XXX and .XXX).

**Ethical Reminder:** All activities confined to my personal lab network. Strict Rules of Engagement mindset practiced — no university, external, or unauthorized scanning.

---
*Progress tracked as part of 4-week ethical pen-testing practice plan.*