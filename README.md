# Ai-NmapX — Parallel Nmap wrapper with AI-assisted analysis & clean HTML reports 🚀

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Reports](https://img.shields.io/badge/Reports-HTML%20by%20default-purple)
![Status](https://img.shields.io/badge/Interactive-TUI%20Menu-brightgreen)
![Speed](https://img.shields.io/badge/Parallel-1--50%20workers-orange)

**Version:** v2.4.2  
**Author:** Dip Kar (HackerBlazeX)  
**License:** MIT

---

## TL;DR ✨
**No need to memorize commands!** Open the **interactive menu** and **just choose options** — Ai-NmapX handles everything end-to-end and gives you a **final polished HTML report** automatically. Chill. ☕  
For power users, rich CLI flags are available — but the menu already covers 99% use-cases.

---

## How it saves your time ⏱️
- 🧭 **Zero memorization:** Presets + menu choices replace long Nmap flags.  
- 🧵 **Parallel scans (1–50 workers):** multi-host jobs finish faster.  
- 🤖 **AI-assisted triage:** automates CVE picking, severity, risky ports, quick fixes — **minutes → seconds**.  
- 🗂️ **HTML by default:** shareable, sorted by risk; no manual formatting.  
- 🔒 **Secure exec + whitelisted extras:** runs right the first time (fewer retries).  
- 🧪 **Quick mode:** discovery → top-ports → AI summary in one go.

---

## What it scans / Capabilities 🔍
Ai-NmapX wraps Nmap with a clean workflow and adds smart analysis:

**Host discovery & mapping**  
- ICMP echo/timestamp/mask, TCP SYN ping, UDP ping, traceroute, list-only, no-DNS.

**TCP stealth & techniques**  
- SYN (half-open), connect, ACK, window, Maimon, NULL, FIN, XMAS.

**UDP / SCTP / IP-protocol**  
- UDP services, SCTP INIT/COOKIE-ECHO, IP protocol discovery.

**Service/OS detection**  
- `-sV`, default NSE scripts, OS detect, aggressive combo (`-A`) as needed.

**Port coverage & speed**  
- Fast (`-F`), Top-100/1000 (with versioning), **Full 0–65535**.

**NSE bundles (focused enumeration)**  
- Safe, discovery, auth, brute (scope!), malware, firewall, **vuln**, http/dns/ftp/smb/snmp/ssl-heartbleed etc.

**Web posture (security hygiene)**  
- TLS versions (1.0/1.1/1.2/1.3), **weak cipher hints**, HSTS + security headers, certificate expiry parsing.

**AI Summary (auto-triage)**  
- CVE extraction, **severity (Low→Critical)**, risky ports/services, **Quick Fixes** (e.g., disable SMBv1, enforce HTTPS/HSTS, SSH key-only), and **Next Steps** (focused NSE, OWASP checks).

**Reporting**
- **HTML (dark, neat) by default**, optional JSON/TXT; hosts sorted by risk; chips for TLS/HSTS; per-target reports.

**Safety**
- **No `shell=True`**, **sanitized `--extra`** (invalid flags auto-drop), `--dry-run` preview, **DNS wildcard guard**.

---

## Install (one command) 📦
\`\`\`bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/HackerBlazeX/Ai-NmapX/main/install.sh)"
\`\`\`

Run the interactive menu:
\`\`\`bash
ai-nmapx -i   # choose options, tool handles the rest and produces final HTML report
\`\`\`

---

## “No Commands Needed” Mode 😎
- Launch \`ai-nmapx -i\`  
- **Pick from 55+ presets & combos** (discovery, stealth, UDP/SCTP/IP, NSE, timing, evasion, posture)  
- Tool runs everything automatically → **AI summary + final HTML report** → done ✅

(README continues similarly with presets, examples, contact — full content will be written)
