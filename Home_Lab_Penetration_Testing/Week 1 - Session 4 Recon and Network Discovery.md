# Week 1: Reconnaissance and Network Discovery  
## Session 4: Service Enumeration and Banner Grabbing  
**Date:** February 8, 2026  
**Target IP:** 192.168.1.183 (labserver.lan – appears to be Ubuntu server running SoftEther VPN)  
**NIST CSF Tie-in:** Identify – Asset Management & Inventory (discovering running services and versions)  
**Goal:** Safely identify open services, versions, and banners on lab systems using active reconnaissance techniques.

### Warm-up (ISC² CC / Google Cybersecurity Review)
**Key Term:** Active reconnaissance  
- Definition: Directly interacting with the target (e.g., sending probes or connection requests) to gather information.  
- Contrast: Passive reconnaissance (observing public sources without touching the target).  
- Risk (even in lab): Can generate logs, trigger Fail2Ban/Auditd, or appear in IDS/monitoring.

### Tools / Commands Used
All executed from Kali Linux laptop.

1. **Host Reachability Check**  
   ```bash
   ping -c 4 192.168.1.183

2. **Full Port + Service + OS Scan
   ```bash
   sudo nmap -sV -O --open -p- 192.168.1.183

3. **Targeted Common Ports + Scripts
```bash
sudo nmap -sV -sC -p 21,22,80,443,445,3306 192.168.1.183

4. ** Manual Banner Grabbing (Netcat)
```bash
nc 192.168.1.183 2222→ 
  Received: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
  ```bash
  nc 192.168.1.183 80