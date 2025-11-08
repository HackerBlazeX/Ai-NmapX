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

## Features 🚀
Ai-NmapX is built to save time and produce shareable results. Key features:

- 🔧 **55+ curated scan presets & combos** (discovery, TCP/UDP/SCTP, NSE bundles, timing & evasion, web posture).
- ⚡ **Parallel scanning**: ThreadPoolExecutor with `--max-workers` (1–50) for fast multi-host jobs.
- 🤖 **AI-assisted triage**: automatic CVE extraction, severity classification (Low→Critical), risk-scoring (0–100), quick fixes and next steps.
- 🌐 **Web posture checks**: TLS versions, weak cipher hints, HSTS and security headers, certificate expiry parsing.
- 🗂️ **Reports**: default **HTML** report (dark, polished) + optional JSON/TXT.
- 🔒 **Secure execution**: sanitized `--extra` flags, no `shell=True`, `--dry-run` preview, DNS wildcard guard.
- 🧾 **Per-target reports** and aggregate AI summary sorted by risk.
- 🧰 **Installer & launcher**: one-line installer creates a venv and `/usr/local/bin/ai-nmapx` launcher.
- 📝 **CI/Lint**: simple GitHub Action lint workflow included.

## Requirements ✅
- Linux (Kali/Ubuntu recommended).  
- nmap (7.x+): `sudo apt install nmap`  
- Python 3.8+ (use `python3 -m venv venv`)  
- Optional recommended Python packages: `pip install -r requirements.txt` (`colorama`, `rich`)
- Git & GitHub CLI (`gh`) for release management (optional).


## Troubleshooting / FAQ ❓
- **nmap not found**: `sudo apt install nmap`  
- **git push rejected / remote mismatch**: run `git fetch origin && git rebase origin/main` (or force only if you know what you do).  
- **SSH key**: `ssh-keygen -t ed25519 -C "you@example.com"` then copy `~/.ssh/id_ed25519.pub` to GitHub → Settings → SSH keys.  
- **gh auth/login issues**: `gh auth login --web` and follow the browser steps.  
- **zsh 'event not found' when pasting heredoc**: run `set +H` before running heredoc commands.  
- **Permission for launcher**: installer writes `/usr/local/bin/ai-nmapx` with sudo — run installer with an account that has sudo.

