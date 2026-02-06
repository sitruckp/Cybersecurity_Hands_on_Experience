# Week 1 – Session 1: Passive Reconnaissance & Lab Topology Mapping

**Date:** February 2026  
**Focus:** Very low-risk, mostly passive information gathering  
**NIST CSF Tie-in:** Identify function – Asset Management & initial Risk Assessment  
**Duration:** 60–90 minutes

## Warm-up (5–10 min)
**Key term:** *Asset* — Anything of value to an organization (hardware, software, data, people, services).  
Quick self-check: Name at least 5 assets in your home lab.  
(Examples: Kali laptop, Ubuntu server, SoftEther VPN tunnel, SSH service, test user accounts…)

## Goals
- Confirm reachability and basic identification of every lab machine from Kali
- Build a simple inventory of IPs, hostnames, MACs
- Practice safest recon: **passive** (using info already available) and minimal active techniques
- Start strong documentation habits

## Activities

1. **Draw/map your lab network** (paper or digital – 5–8 min)  
   Sketch: Kali → VPN → servers/laptops, note internal IP ranges (e.g., 192.168.x.0/24 or 10.x.x.x).  
   → This becomes your mental “scope boundary”.

2. **Check your own addressing & existing ARP table** (10 min)
   ```bash
   ip -brief address show
   arp -a
   # or more modern:
   ip neigh show