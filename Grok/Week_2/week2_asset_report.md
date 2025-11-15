# Week 2: Asset Security Lab Report

**Analyst:** Kevin Curtis | **Date:** 2025-11-14  
**Environment:** Kali (attacker) → Debian 13 (target)  
**Credentials:** ISC² CC, Google Cybersecurity Pro

## Objectives Achieved
1. **Inventory assets** using `ss`, `ps`, and Nmap  
2. **Classify data** (public vs. confidential)  
3. **Encrypt sensitive data** with GPG (RSA 2048)

## Asset Inventory Table

| Asset            | Type    | Sensitivity | Protection                     | External Visibility |
|------------------|---------|-------------|--------------------------------|---------------------|
| SSH              | Service | Medium      | UFW allow, **port 2222**, key-only | `open` (required) |
| PostgreSQL       | Service | High        | Localhost-only + UFW           | `filtered` (secure) |
| DNS (53)         | Service | Low         | systemd-resolved               | `filtered` (secure) |
| LLMNR (5355)     | Service | Low         | mDNS                           | `filtered` (secure) |
| `confidential.txt` | File  | High        | **GPG encrypted** (ID: `5F08A7E59DD7BD39`) | N/A |

## Hardening Validation (Nmap from Kali)
```text
PORT     STATE    SERVICE    VERSION
2222/tcp open     ssh        OpenSSH 10.0p2
53/tcp   filtered domain
5355/tcp filtered llmnr
5432/tcp filtered postgresql
