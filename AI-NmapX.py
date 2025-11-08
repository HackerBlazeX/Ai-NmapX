#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Ai-NmapX — Parallel + Rich TUI (Final Pro, Secure Exec + Heuristics)
# Created by Dip Kar (engineered with ChatGPT)
# License: MIT
#
# WARNING: Use only on systems you own or have explicit written permission to test.
# Unauthorised scanning may be illegal. The author is not responsible for misuse.
#
# Highlights:
# - 45+ Nmap presets (TCP/UDP/SCTP/IP, stealth, evasion, timing, NSE)
# - Interactive menu + CLI
# - Parallel scans (ThreadPoolExecutor) with --max-workers (clamped 1..50)
# - Rich TUI progress bars (auto-fallback if 'rich' missing)
# - AI Analyzer: CVEs, severity, risky ports, fixes/next steps
# - Web Posture AI: TLS versions, weak ciphers, HSTS & headers, cert expiry
# - DNS Wildcard Guard: flags wildcard DNS
# - Reports: HTML (dark, neat)  [Default: ONLY HTML]  (TXT/JSON optional via CLI)
# - Secure exec: NO shell=True; whitelist for --extra; --dry-run
# - Patched heuristics: aggressive-scan risky phrases -> VULNERABLE + better severity
#
# Quick:
#   python3 ai_nmapx.py -i
#   python3 ai_nmapx.py -t scanme.nmap.org -s all --sudo --save-html --max-workers 6
#
# Reqs:
#   apt install nmap python3-colorama
#   (optional) apt install python3-rich   # or: pip install rich (in venv)

from __future__ import annotations
import os, sys, re, json, shutil, subprocess, argparse, socket, shlex, warnings
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "2.4.2"

# Optional: keep UI clean from FutureWarnings
warnings.filterwarnings("ignore", category=FutureWarning)

# ---------- Color ----------
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except Exception:  # fallback
    class _Dummy:
        RESET_ALL=""; RED=CYAN=YELLOW=GREEN=MAGENTA=WHITE=BLUE=""
        BRIGHT=""; DIM=""
    Fore=_Dummy(); Style=_Dummy()
    def init(*a, **k): pass

# ANSI escape (if ever needed)
ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

# ---------- Optional Rich TUI ----------
HAVE_RICH = False
try:
    from rich.progress import Progress, BarColumn, TimeRemainingColumn, SpinnerColumn, TextColumn, MofNCompleteColumn
    from rich.console import Console
    HAVE_RICH = True
except Exception:
    HAVE_RICH = False

CONSOLE = Console() if HAVE_RICH else None

# ---------- Config ----------
REPORT_DIR = "reports"
# Default: ONLY HTML (as requested). Can override with CLI flags.
DEFAULT_SAVE_TXT  = False
DEFAULT_SAVE_JSON = False
DEFAULT_SAVE_HTML = True

# ---------- Banner (centered + highlighted) ----------
BANNER_LINES = [
    "╔═╗╔═╗╔╦╗  Ai-NmapX",
    "║A║║i║║║║  Created by: DIP KAR",
    "╚═╝╚═╝╩ ╩  Recon | Score | Fix"
]

def _terminal_width() -> int:
    try:
        return shutil.get_terminal_size((80, 20)).columns
    except Exception:
        return 80

def render_banner() -> str:
    width = _terminal_width()
    colored_lines = []
    for raw in BANNER_LINES:
        parts = raw.split("  ", 1)
        frame = parts[0]
        text = parts[1] if len(parts) > 1 else ""

        frame_col = Fore.CYAN + Style.BRIGHT
        if "Ai-NmapX" in text:
            text_col = Fore.YELLOW + Style.BRIGHT
        elif "Created by" in text:
            text_col = Fore.MAGENTA + Style.BRIGHT
        else:
            text_col = Fore.GREEN + Style.BRIGHT

        line_colored = frame_col + frame + Style.RESET_ALL + "  " + text_col + text + Style.RESET_ALL

        # visible length without ANSI (compute from plain parts)
        visible_len = len(frame + "  " + text)
        pad = max(0, (width - visible_len) // 2)
        colored_lines.append(" " * pad + line_colored)

    status_text = f"v{__version__}  Rich TUI:{'ON' if HAVE_RICH else 'OFF'}  Reports default: HTML only"
    status_pad = max(0, (width - len(status_text)) // 2)
    status_line = " " * status_pad + Fore.WHITE + status_text + Style.RESET_ALL

    return "\n".join(colored_lines + [status_line, ""])

# ---------- Presets ----------
SCAN_PRESETS: Dict[str,str] = {
    # Discovery
    "ping":               "-sn",
    "icmp_echo_ping":     "-sn -PE",
    "icmp_ts_ping":       "-sn -PP",
    "icmp_mask_ping":     "-sn -PM",
    "tcp_syn_ping":       "-sn -PS",
    "udp_ping":           "-sn -PU",
    "list":               "-sL",
    "no_dns":             "-n",
    "traceroute":         "--traceroute",

    # TCP core
    "syn":                "-sS",
    "tcp_connect":        "-sT",
    "ack":                "-sA",
    "window":             "-sW",
    "maimon":             "-sM",
    "null":               "-sN",
    "fin":                "-sF",
    "xmas":               "-sX",

    # UDP / SCTP / IP-proto
    "udp":                "-sU",
    "sctp_init":          "-sY",
    "sctp_cookie_echo":   "-sZ",
    "ip_proto":           "-sO",

    # Detection
    "version":            "-sV",
    "default_scripts":    "-sC",
    "os":                 "-O",
    "aggressive":         "-A",

    # Ports & speed
    "fast":               "-F",
    "top100":             "--top-ports 100 -sV",
    "top1000":            "--top-ports 1000 -sV",
    "full_port":          "-p-",

    # NSE focus
    "nse_safe":           '--script "safe"',
    "nse_discovery":      '--script "discovery"',
    "nse_auth":           '--script "auth"',
    "nse_brute":          '--script "brute"',
    "nse_malware":        '--script "malware"',
    "vuln":               "--script vuln",
    "firewall":           "--script firewall-bypass",
    "http_enum":          '--script "http-enum"',
    "dns_enum":           '--script "dns-brute"',
    "ftp_anon":           '--script "ftp-anon"',
    "smb_enum":           '--script "smb-enum*"',
    "snmp_enum":          '--script "snmp*"',
    "ssl_heartbleed":     "--script ssl-heartbleed",

    # Web posture bundle
    "web_posture":        '--script "http-title,http-headers,ssl-enum-ciphers,ssl-cert" -p 80,443 -sV',

    # Evasion / spoofing (legal scope only)
    "fragment":           "-f",
    "decoy":              "-D RND:10",
    "source_port_53":     "-g 53",
    "spoof_mac":          "--spoof-mac 0",
    "data_len_120":       "--data-length 120",
    "ttl_44":             "--ttl 44",

    # Timing
    "timid":              "-T0",
    "polite":             "-T2",
    "normal_timing":      "-T3",
    "aggr_timing":        "-T4",
    "insane":             "-T5",

    # Combined discovery
    "all_discovery":      "-Pn -sS -sV -O --traceroute",
}

# Curated "all" sequence
ALL_SCANS_SEQ = [
    "ping", "top100", "version", "os", "default_scripts",
    "vuln", "http_enum", "web_posture", "dns_enum", "smb_enum"
]

# ---------- Utils ----------
def clear(): os.system('cls' if os.name == 'nt' else 'clear')
def ensure_reports_dir(out_dir: Optional[str]=None):
    d = out_dir or REPORT_DIR
    os.makedirs(d, exist_ok=True)
def sanitize_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9\-_\.]', '_', s)[:180]
def is_root_user() -> bool:
    return os.name != 'nt' and hasattr(os, "geteuid") and os.geteuid() == 0

IPV4_RX = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
def is_domain(x: str) -> bool:
    return ('.' in x) and (not IPV4_RX.match(x))

def check_prereqs():
    if not shutil.which("nmap"):
        print(Fore.RED + "nmap not installed. Install: sudo apt install nmap"); sys.exit(1)

def parse_targets(user_input: str) -> List[str]:
    user_input = (user_input or "").strip()
    if not user_input: return []
    t=[]
    if user_input.startswith("@"):
        path=user_input[1:].strip()
        if not os.path.isfile(path):
            print(Fore.RED + f"[!] File not found: {path}"); return []
        with open(path,"r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"): continue
                t += [p for p in re.split(r"[,\s]+", line) if p]
    else:
        t = [p for p in re.split(r"[,\s]+", user_input) if p]
    seen=set(); uniq=[]
    for x in t:
        if x not in seen: uniq.append(x); seen.add(x)
    return uniq

# ---------- Secure EXTRA options (whitelist) ----------
ALLOWED_LONG = {
    "--reason","--open","--defeat-rst-ratelimit","--max-retries",
    "--min-rate","--max-rate","--scan-delay","--script-timeout",
    "--ttl","--data-length","--spoof-mac","--version-light","--version-all",
    "--traceroute","--disable-arp-ping","--source-port"
}
ALLOWED_SHORT = {"-T","-n","-Pn","-PS","-PA","-PU","-PE","-PP","-PM","-g","-f","-F"}

_MAC_FULL_RX = re.compile(r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$')

def _valid_mac_token(val: str) -> bool:
    """
    Allow '0' (random vendor), or full 6-byte MAC (colon-separated).
    """
    if val == "0":
        return True
    return bool(_MAC_FULL_RX.match(val))

def sanitize_extra_opts(extra: str) -> List[str]:
    """
    Keep only whitelisted flags. Validate values; warn on dropped tokens.
    """
    if not extra: return []
    toks = shlex.split(extra)
    safe: List[str] = []
    dropped: List[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in ALLOWED_SHORT or tok in ALLOWED_LONG:
            # Flags that take a value next
            if tok in {"--max-retries","--min-rate","--max-rate","--scan-delay","--script-timeout",
                       "--ttl","--data-length","--source-port","-PS","-PA","-PU","-PE","-PP","-PM","-g","-T"}:
                safe.append(tok)
                if i+1 < len(toks) and not toks[i+1].startswith("-"):
                    safe.append(toks[i+1]); i+=1
                else:
                    dropped.append(tok + " (missing value)")
            elif tok == "--spoof-mac":
                if i+1 < len(toks) and not toks[i+1].startswith("-") and _valid_mac_token(toks[i+1]):
                    safe.append(tok); safe.append(toks[i+1]); i+=1
                else:
                    dropped.append(tok + " (invalid or missing value)")
            else:
                safe.append(tok)
        elif tok.startswith("-T") and tok in {"-T0","-T1","-T2","-T3","-T4","-T5"}:
            safe.append(tok)
        elif tok in {"-Pn","-n"}:
            safe.append(tok)
        else:
            dropped.append(tok)
        i+=1
    if dropped:
        print(Fore.YELLOW + "[!] Some extra options were dropped (not allowed/invalid): " + ", ".join(dropped))
    return safe

# ---------- Command builder & runner (NO shell=True) ----------
def build_nmap_args(preset_or_args: str, targets: List[str],
                    custom_ports: Optional[str]=None,
                    use_sudo: bool=False, extra_opts: Optional[str]="") -> Optional[List[str]]:
    if not targets: return None
    base_args = SCAN_PRESETS.get(preset_or_args, preset_or_args)
    args: List[str] = shlex.split(base_args)
    if custom_ports:
        args += ["-p", custom_ports]
    args += sanitize_extra_opts(extra_opts or "")
    full = (["sudo"] if (use_sudo and not is_root_user()) else []) + ["nmap"] + args + targets
    return full

def run_capture(cmd_args: List[str], timeout: Optional[int]=None, dry_run: bool=False) -> str:
    if dry_run:
        return "[DRY-RUN] " + " ".join(shlex.quote(x) for x in cmd_args) + "\n"
    try:
        proc = subprocess.run(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return proc.stdout
    except subprocess.TimeoutExpired:
        return "\n[!] Command timed out.\n"
    except KeyboardInterrupt:
        return "\n[!] Scan interrupted by user.\n"
    except Exception as e:
        return f"\n[!] Error: {e}\n"

def run_stream(cmd_args: List[str], dry_run: bool=False) -> str:
    if dry_run:
        line = "[DRY-RUN] " + " ".join(shlex.quote(x) for x in cmd_args) + "\n"
        print(Fore.GREEN + line)
        return line
    print(Fore.GREEN + f"\n[+] Running (stream): " + " ".join(shlex.quote(x) for x in cmd_args) + "\n")
    out=[]
    try:
        p = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in iter(p.stdout.readline, ''):
            out.append(line); print(line.rstrip())
        p.wait()
    except KeyboardInterrupt:
        try: p.terminate()
        except Exception: pass
        out.append("\n[!] Interrupted by user.\n")
        print(Fore.RED + "\n[!] Interrupted.\n")
    except Exception as e:
        out.append(f"\n[!] Streaming error: {e}\n")
    return "".join(out)

# ---------- Heuristics & AI (patched) ----------
NEGATIVE_VULN_PATTERNS = (
    "couldn't find any", "no vulnerabilities", "not vulnerable",
    "0 vulnerabilities", "no vuln", "did not find", "false positive",
    "could not confirm", "appears to be patched", "not affected"
)

CVE_RX = re.compile(r'\bCVE-\d{4}-\d+\b', re.I)
STRICT_POS_REGEXES = [r'\bCVE-\d{4}-\d+\b', r'\bVULNERABLE\b', r'\bis vulnerable\b', r'\bState:\s*VULNERABLE\b']
RELAXED_EXTRA_REGEXES = [r'\bpossibly vulnerable\b', r'\bpotentially vulnerable\b', r'\bmay be vulnerable\b']

EXTRA_VULN_PHRASES = [
    "anonymous ftp login", "anonymous ftp login allowed", "anonymous login", "anonymous ftp",
    "bindshell", "bind shell", "backdoor", "root shell", "as root",
    "sslv2 supported", "sslv3 supported", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1",
    "message_signing: disabled", "signing: disabled",
    "unreal", "unrealircd", "vsftpd 2.3.4", "proftpd 1.3.1",
    "rsh", "rexecd", "telnet",
    "vnc authentication", "x11", "nfs", "smb",
    "default password", "default creds", "default credentials",
    "expired certificate", "not valid after", "old version", "outdated"
]

SEVERITY_KEYWORDS = {
    "critical": [
        r"remote code execution", r"rce", r"unauth", r"pre-auth",
        r"privilege escalation", r"arbitrary code", r"bindshell", r"bind shell",
        r"root shell", r"backdoor", r"unreal", r"vsftpd\s*2\.3\.4"
    ],
    "high": [
        r"code execution", r"command injection", r"sql injection", r"ssrf", r"deserialization",
        r"directory traversal", r"auth bypass", r"sslv2", r"sslv3", r"expired certificate",
        r"message_signing: disabled", r"nfs", r"smb", r"telnet", r"rsh", r"rexecd"
    ],
    "medium": [
        r"info leak", r"disclosure", r"path leak", r"xss", r"open redirect",
        r"weak cipher", r"anonymous login", r"anonymous ftp", r"vnc authentication"
    ],
    "low": [
        r"dos", r"denial of service", r"banner", r"misconfig", r"self-signed", r"deprecated"
    ]
}

def looks_negative_vuln(line_lower: str) -> bool:
    return any(p in line_lower for p in NEGATIVE_VULN_PATTERNS)

def looks_positive_vuln(line: str, mode: str="strict") -> bool:
    if not line:
        return False
    L = line.lower()
    if looks_negative_vuln(L):
        return False
    for rx in STRICT_POS_REGEXES:
        if re.search(rx, line, re.I):
            return True
    if mode == "relaxed":
        for rx in RELAXED_EXTRA_REGEXES:
            if re.search(rx, line, re.I):
                return True
    for phrase in EXTRA_VULN_PHRASES:
        if phrase in L:
            return True
    if re.search(r'vsftpd\s*2\.3\.4', L, re.I):
        return True
    return False

def classify_severity(text: str) -> str:
    if not text:
        return "Low"
    L = text.lower()
    if CVE_RX.search(text):
        for pat in SEVERITY_KEYWORDS.get("critical", []):
            if re.search(pat, L):
                return "Critical"
        return "High"
    for sev, pats in SEVERITY_KEYWORDS.items():
        for pat in pats:
            if re.search(pat, L):
                return {"critical":"Critical","high":"High","medium":"Medium","low":"Low"}[sev]
    for phrase in EXTRA_VULN_PHRASES:
        if phrase in L:
            if any(x in phrase for x in ("bindshell","backdoor","root shell","unreal","vsftpd")):
                return "Critical"
            if any(x in phrase for x in ("sslv2","sslv3","message_signing","nfs","smb","telnet","rsh","rexecd")):
                return "High"
            return "Medium"
    return "Low"

def risk_label(score: int) -> Tuple[str, str]:
    """Return (label, color_code)"""
    if score >= 75:   return ("CRITICAL", Fore.RED + Style.BRIGHT)
    if score >= 50:   return ("HIGH",     Fore.MAGENTA + Style.BRIGHT)
    if score >= 25:   return ("MEDIUM",   Fore.YELLOW + Style.BRIGHT)
    return ("LOW",     Fore.GREEN + Style.BRIGHT)

def simple_analyze(output: str, vuln_mode: str="strict") -> Tuple[List[Tuple[str,str]], Dict[str,int]]:
    findings=[]; stats={"OPEN":0,"CLOSED":0,"FILTERED":0,"VULNERABLE":0,"INFO":0}
    for line in output.splitlines():
        L=line.lower().strip()
        if not L: continue
        if re.search(r'\b\d{1,5}/(tcp|udp|sctp)\b\s+open', L):
            findings.append((line,"OPEN")); stats["OPEN"]+=1; continue
        if "filtered" in L:
            findings.append((line,"FILTERED")); stats["FILTERED"]+=1; continue
        if re.search(r'\bclosed\b', L):
            findings.append((line,"CLOSED")); stats["CLOSED"]+=1; continue
        if looks_positive_vuln(line, vuln_mode):
            findings.append((line,"VULNERABLE")); stats["VULNERABLE"]+=1; continue
        if "script execution failed" in L or "error" in L:
            findings.append((line,"INFO")); stats["INFO"]+=1; continue
        findings.append((line,"INFO")); stats["INFO"]+=1
    return findings, stats

RISK_PORTS = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",53:"DNS",69:"TFTP",80:"HTTP",
    110:"POP3",111:"RPC",123:"NTP",135:"MSRPC",139:"NetBIOS",143:"IMAP",161:"SNMP",389:"LDAP",
    443:"HTTPS",445:"SMB",465:"SMTPS",500:"ISAKMP",587:"SMTP-Sub",631:"IPP",873:"rsync",
    1080:"SOCKS",1433:"MSSQL",1521:"Oracle",2049:"NFS",2375:"Docker",2376:"Docker-TLS",
    27017:"MongoDB",27018:"MongoDB",27019:"MongoDB",3306:"MySQL",3389:"RDP",3632:"distcc",
    4369:"EPMD",5000:"HTTP-Alt",5432:"Postgres",5601:"Kibana",5900:"VNC",
    5985:"WinRM",5986:"WinRM-SSL",6379:"Redis",7001:"WebLogic",8000:"http-alt",
    8080:"HTTP-Proxy",8081:"HTTP-Alt",8089:"Splunk",9000:"SonarQube",9200:"Elasticsearch",
    11211:"Memcached"
}

# ---------- DNS Wildcard Guard ----------
def _rand_label(n=10) -> str:
    import random, string
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))

def dns_wildcard_check(domain: str) -> bool:
    try:
        test = f"{_rand_label()}.{domain}"
        socket.getaddrinfo(test, None)
        return True
    except Exception:
        return False

# ---------- Web Posture Parser ----------
TLS_VER_RX = re.compile(r'\b(TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3|SSLv3)\b', re.I)
CERT_AFTER_RX = re.compile(r'Not valid after:\s*(.+)', re.I)
SEC_HDRS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
WEAK_CIPHER_HINTS = [r'\bRC4\b', r'\b3DES\b', r'\bDES\b', r'\bNULL\b', r'\bEXPORT\b', r'CBC', r'weak']

def parse_web_posture(host_text: str) -> Dict[str, Any]:
    tls_versions=set(m.group(1).upper() for m in TLS_VER_RX.finditer(host_text))
    weak_flags=set()
    for pat in WEAK_CIPHER_HINTS:
        if re.search(pat, host_text, re.I):
            weak_flags.add(re.sub(r'\\b','',pat).strip('r').strip('()').replace('\\',''))
    headers_found=[]
    for h in SEC_HDRS:
        if re.search(rf'^{re.escape(h)}\s*:\s*.+', host_text, re.I|re.M):
            headers_found.append(h)
    hsts_present = any(h.lower()=="strict-transport-security" for h in headers_found)

    cert_expiry=None
    m=CERT_AFTER_RX.search(host_text)
    if m: cert_expiry=m.group(1).strip()

    issues=[]
    if "TLSV1.0" in tls_versions or "TLSV1.1" in tls_versions or "SSLV3" in tls_versions:
        issues.append("Legacy TLS enabled (<=1.1/SSLv3).")
    if not hsts_present and ("443/tcp" in host_text or "https" in host_text.lower()):
        issues.append("HSTS missing on HTTPS.")
    if weak_flags:
        issues.append("Weak cipher hints: " + ", ".join(sorted(weak_flags)))

    return {
        "tls_versions": sorted(tls_versions),
        "security_headers": sorted(headers_found),
        "hsts": hsts_present,
        "cert_not_after": cert_expiry or "",
        "issues": issues
    }

# ---------- Host section split ----------
def extract_hosts_sections(raw_text: str) -> Dict[str,str]:
    sections={}; current=None; buf=[]
    for line in raw_text.splitlines():
        m=re.search(r"Nmap scan report for (.+)", line)
        if m:
            if current and buf: sections[current]="\n".join(buf); buf=[]
            hostline=m.group(1).strip()
            m2=re.search(r"(.*)\((\d+\.\d+\.\d+\.\d+)\)", hostline)
            current = m2.group(2).strip() if m2 else hostline
        if current: buf.append(line)
    if current and buf: sections[current]="\n".join(buf)
    return sections if sections else {"ALL": raw_text}

# ---------- AI Assist ----------
def ai_assist_analysis(raw: str, vuln_mode: str="strict") -> Dict[str,Any]:
    hosts=extract_hosts_sections(raw)
    report={"hosts":{}, "overall":{"high_risk_hosts":0,"total_hosts":len(hosts), "notes": []}}
    for host, text in hosts.items():
        open_ports=[]; services=[]; vulns=[]; cves=set()
        sev_counts={"Critical":0,"High":0,"Medium":0,"Low":0}
        for line in text.splitlines():
            m=re.search(r"(\d{1,5})/(tcp|udp|sctp)\s+open\s+([A-Za-z0-9\-\._]+)?", line, re.I)
            if m:
                p=int(m.group(1)); proto=m.group(2).lower()
                svc=(m.group(3) or "").lower()
                open_ports.append((p,proto))
                if svc: services.append(f"{svc}({p}/{proto})")
            if looks_positive_vuln(line, vuln_mode):
                sev=classify_severity(line); sev_counts[sev]+=1
                vulns.append(f"[{sev}] {line.strip()}")
            for c in CVE_RX.findall(line):
                cves.add(c.upper())

        score=0
        for p,_ in open_ports:
            base=5
            if p in (21,23,69,110,143,161,389,445,1521,2049,2375,3389,5432,5900,5985,5986,6379,11211): base=12
            if p in (20,21,22,23,25,53,80,139,443,445,3389,8080): base+=6
            score+=base
        score += 20*sev_counts["Critical"] + 12*sev_counts["High"] + 6*sev_counts["Medium"] + 2*sev_counts["Low"]
        score=max(0,min(100,score))

        web_posture = parse_web_posture(text)
        if web_posture.get("issues"):
            score = min(100, score + 6)

        risky_ports=[f"{p}/{proto}:{RISK_PORTS.get(p,'?')}" for p,proto in open_ports if p in RISK_PORTS]
        fixes=[]
        if any(p in (21,23,110,143) for p,_ in open_ports): fixes.append("Disable plaintext (FTP/Telnet/POP/IMAP).")
        if any(p in (445,139) for p,_ in open_ports): fixes.append("SMB harden: disable SMBv1, enable signing, patch.")
        if any(p==3389 for p,_ in open_ports): fixes.append("RDP: enable NLA, restrict to VPN.")
        if any("ssh" in s for s in services): fixes.append("SSH: key-only auth, disable password, fail2ban.")
        if any("http(" in s or "http-alt" in s for s in services) or any(p==80 for p,_ in open_ports):
            fixes.append("HTTP: force HTTPS (HSTS), patch stack, hide banners.")
        if "redis" in " ".join(services): fixes.append("Redis: bind 127.0.0.1, requirepass, ACLs.")
        if "mongodb" in " ".join(services): fixes.append("MongoDB: enable auth, bind local/VPN, TLS.")
        if not open_ports: fixes.append("No open ports — firewall/ACLs effective.")
        if not fixes: fixes.append("Apply standard hardening + patch cadence.")

        next_steps=[
            "Verify versions with -sV/-O/-A; confirm manually.",
            "If web: content discovery + OWASP Top 10.",
            "Run focused NSE (safe first); intrusive only with scope.",
            "Close unused ports; tighten firewall/ACLs."
        ]

        report["hosts"][host]={
            "open_ports":[f"{p}/{proto}" for p,proto in sorted(open_ports)],
            "services":services,
            "risky_ports":risky_ports,
            "vuln_hits":vulns[:60],
            "cves":sorted(cves),
            "severity_count":sev_counts,
            "risk_score":score,
            "web_posture": web_posture,
            "fixes":fixes,
            "next":next_steps
        }
        if score>=60: report["overall"]["high_risk_hosts"]+=1
    return report

def print_ai_summary(ai_rep: Dict[str,Any]) -> None:
    print(Fore.WHITE + "\n========== Ai-NmapX Final Summary ==========\n")
    oh=ai_rep.get("overall",{})
    print(Fore.CYAN + f"Total Hosts: {oh.get('total_hosts',0)} | High-Risk Hosts: {oh.get('high_risk_hosts',0)}\n")
    if oh.get("notes"):
        for n in oh["notes"]:
            print(Fore.YELLOW + f"Note: {n}")
        print()
    for host,data in ai_rep["hosts"].items():
        label, color = risk_label(data.get("risk_score",0))
        print(Fore.MAGENTA + f"[Host] {host} " + color + f"[{label}]" + Style.RESET_ALL)
        print(Fore.YELLOW + f"  Risk Score: {data['risk_score']}/100")
        sc=data.get("severity_count",{})
        print(Fore.RED + f"  Sev: C:{sc.get('Critical',0)} H:{sc.get('High',0)} M:{sc.get('Medium',0)} L:{sc.get('Low',0)}")
        print(Fore.GREEN + f"  Open Ports : {', '.join(data['open_ports']) if data['open_ports'] else 'None'}")
        if data["risky_ports"]:
            print(Fore.RED + f"  Risky Ports: {', '.join(data['risky_ports'])}")
        if data.get("cves"):
            print(Fore.RED + f"  CVEs       : {', '.join(data['cves'])}")
        wp=data.get("web_posture",{})
        chips=[]
        if wp.get("tls_versions"): chips.append("TLS:" + "/".join(wp["tls_versions"]))
        if wp.get("hsts"): chips.append("HSTS:Yes")
        elif any(p.startswith("443/") for p in data["open_ports"]): chips.append("HSTS:No")
        if wp.get("issues"): chips.append("Issues:" + str(len(wp["issues"])))
        if chips:
            print(Fore.CYAN + "  Web Posture: " + " | ".join(chips))
        if wp.get("issues"):
            for i in wp["issues"][:3]:
                print(Fore.CYAN + f"    - {i}")
        if data["vuln_hits"]:
            print(Fore.RED + f"  Vuln Lines: {min(3,len(data['vuln_hits']))} shown")
            for v in data['vuln_hits'][:3]:
                print(Fore.RED + f"    - {v}")
        print(Fore.CYAN + "  Quick Fixes:")
        for f in data["fixes"][:3]:
            print(Fore.CYAN + f"    - {f}")
        print(Fore.WHITE)
    print(Fore.WHITE + "============================================\n")

# ---------- Reports ----------
def escape_html(s: str) -> str:
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def render_web_posture_html(wp: Dict[str,Any]) -> str:
    if not wp: return ""
    items=[]
    if wp.get("tls_versions"): items.append(f"TLS: {'/'.join(wp['tls_versions'])}")
    items.append("HSTS: Yes" if wp.get("hsts") else "HSTS: No")
    if wp.get("security_headers"):
        items.append("Headers: " + ", ".join(wp["security_headers"]))
    if wp.get("cert_not_after"):
        items.append("Cert Expires: " + escape_html(wp["cert_not_after"]))
    if wp.get("issues"):
        items.append("Issues: " + "; ".join(wp["issues"]))
    return "<br>".join(escape_html(x) for x in items)

def save_reports(label: str, scan_key: str, raw: str, findings: List[Tuple[str,str]],
                 stats: Dict[str,int], ai_rep: Optional[Dict]=None,
                 save_txt: bool=True, save_json: bool=True, save_html: bool=False,
                 out_dir: Optional[str]=None) -> None:
    ensure_reports_dir(out_dir)
    d = out_dir or REPORT_DIR
    safe = sanitize_filename(label if label else "scan")
    ts = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S_UTC")
    base = f"{safe}_scan_{scan_key}_{ts}"
    if save_txt:
        txt_path=os.path.join(d, base+".txt")
        with open(txt_path,"w",encoding="utf-8") as f:
            f.write("Ai-NmapX - Scan Report\n")
            f.write(f"Target(s): {label}\nScan Type: {scan_key}\nGenerated: {ts}\n")
            f.write("="*80 + "\n\nRAW OUTPUT\n\n"+raw+"\n\nANALYSIS SUMMARY\n\n")
            for k,v in stats.items(): f.write(f"{k}: {v}\n")
            f.write("\nDETAILED FINDINGS\n\n")
            for l,s in findings: f.write(f"{s} -> {l}\n")
            if ai_rep:
                f.write("\nAi-NmapX FINAL SUMMARY (JSON)\n\n")
                f.write(json.dumps(ai_rep, indent=2))
        print(Fore.CYAN + f"[+] Saved TXT report: {txt_path}")
    if save_html:
        html_path=os.path.join(d, base+".html")
        # Sort hosts by risk desc for better attention
        hosts_sorted = []
        if ai_rep and "hosts" in ai_rep:
            hosts_sorted = sorted(ai_rep["hosts"].items(), key=lambda kv: kv[1].get("risk_score",0), reverse=True)
        html = "<!doctype html><html><head><meta charset='utf-8'><title>Ai-NmapX Report</title>"
        html+= "<style>body{font-family:Inter,Arial,Helvetica,sans-serif;padding:18px;background:#0b1020;color:#e6e6ea}"
        html+= "h2,h3{color:#7cc4ff} .card{background:#121734;border:1px solid #1f2a54;border-radius:12px;padding:16px;margin:12px 0}"
        html+= "pre{background:#0a0e1c;color:#d1d7ff;padding:12px;border-radius:8px;overflow:auto}"
        html+= ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}"
        html+= ".pill{display:inline-block;padding:4px 10px;border-radius:999px;background:#1a245a;color:#9ed0ff;margin-right:6px;font-size:12px}"
        html+= ".badge{display:inline-block;padding:4px 10px;border-radius:8px;margin-left:6px;font-size:12px}"
        html+= ".crit{background:#5f1120;color:#ffb3c0}.high{background:#3a134d;color:#e5bfff}.med{background:#524a18;color:#fff3a1}.low{background:#183a20;color:#b6ffd1}"
        html+= "code{color:#98e6ff}</style></head><body>"
        html+= f"<h2>Ai-NmapX — {escape_html(label)} — {ts}</h2>"
        html+= f"<div class='grid'><div class='card'><h3>Preset/Type</h3><pre>{escape_html(scan_key)}</pre></div>"
        html+= f"<div class='card'><h3>Stats</h3><pre>"+ "\n".join(f"{k}: {v}" for k,v in stats.items()) + "</pre></div></div>"
        if hosts_sorted:
            html+= "<div class='card'><h3>AI Summary (hosts sorted by risk)</h3>"
            for host, data in hosts_sorted:
                score = data.get("risk_score",0)
                if score>=75: cls,label="crit","CRITICAL"
                elif score>=50: cls,label="high","HIGH"
                elif score>=25: cls,label="med","MEDIUM"
                else: cls,label="low","LOW"
                pills=[]
                pills.append(f"<span class='pill'>Risk {score}/100</span><span class='badge {cls}'>{label}</span>")
                wp=data.get("web_posture",{})
                if wp.get("tls_versions"): pills.append(f"<span class='pill'>TLS {'/'.join(wp['tls_versions'])}</span>")
                pills.append(f"<span class='pill'>HSTS {'Yes' if wp.get('hsts') else 'No'}</span>")
                html+= f"<h4>{escape_html(host)}</h4>" + " ".join(pills)
                html+= "<pre>"+ escape_html("Open: " + ", ".join(data.get("open_ports",[]))) +"</pre>"
                if wp:
                    html+= "<div style='margin:8px 0'>"+ render_web_posture_html(wp) +"</div>"
            html+= "</div>"
        if ai_rep is None:
            html+= "<div class='card'><h3>AI Summary</h3><pre>No AI summary available.</pre></div>"
        html+= "<div class='card'><h3>Raw Output</h3><pre>"+escape_html(raw)+"</pre></div>"
        html+= "<div class='card'><h3>Findings</h3><pre>" + "\n".join(f"{s} -> {escape_html(l)}" for l,s in findings) + "</pre></div>"
        html+= "<div class='card'><small>Generated by Ai-NmapX • Created by Dip Kar • v"+__version__+"</small></div>"
        html+= "</body></html>"
        with open(html_path,"w",encoding="utf-8") as f: f.write(html)
        print(Fore.CYAN + f"[+] Saved HTML report: {html_path}")
    if save_json:
        json_path=os.path.join(d, base+".json")
        data={"targets":label,"scan_type":scan_key,"generated":ts,"stats":stats,
              "findings":[{"tag":s,"line":l} for l,s in findings],"raw":raw,"ai_summary":ai_rep or {}}
        with open(json_path,"w",encoding="utf-8") as f: json.dump(data,f,indent=2)
        print(Fore.CYAN + f"[+] Saved JSON report: {json_path}")

# ---------- Parallel runners ----------
def _exec_capture_task(cmd_args: List[str], dry_run: bool=False) -> str:
    return run_capture(cmd_args, dry_run=dry_run)

def parallel_run_targets(preset: str, targets: List[str], custom_ports: str, use_sudo: bool,
                         extra_opts: str, max_workers: int, dry_run: bool=False) -> Dict[str,str]:
    target_cmds = {t: build_nmap_args(preset, [t], custom_ports, use_sudo, extra_opts) for t in targets}
    outputs: Dict[str,str] = {}
    if HAVE_RICH:
        with Progress(SpinnerColumn(), TextColumn("[bold magenta]Batch Scan[/]"),
                      BarColumn(), MofNCompleteColumn(), TimeRemainingColumn()) as prog:
            task = prog.add_task("Scanning targets", total=len(targets))
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                future_map = { ex.submit(_exec_capture_task, cmd, dry_run): t for t, cmd in target_cmds.items() }
                for fut in as_completed(future_map):
                    t = future_map[fut]
                    try:
                        outputs[t] = fut.result()
                    except Exception as e:
                        outputs[t] = f"\n[!] Error on {t}: {e}\n"
                    prog.advance(task, 1)
    else:
        print(Fore.YELLOW + f"[~] Parallel scanning {len(targets)} target(s) with {max_workers} workers...")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            future_map = { ex.submit(_exec_capture_task, cmd, dry_run): t for t, cmd in target_cmds.items() }
            for fut in as_completed(future_map):
                t = future_map[fut]
                try: outputs[t] = fut.result()
                except Exception as e: outputs[t] = f"\n[!] Error on {t}: {e}\n"
    return outputs

def parallel_run_presets(presets: List[str], targets: List[str], use_sudo: bool,
                         max_workers: int, dry_run: bool=False) -> Dict[str,str]:
    preset_cmds = {k: build_nmap_args(k, targets, None, use_sudo, "") for k in presets}
    outputs: Dict[str,str] = {}
    if HAVE_RICH:
        with Progress(SpinnerColumn(), TextColumn("[bold magenta]All-Scans[/]"),
                      BarColumn(), MofNCompleteColumn(), TimeRemainingColumn()) as prog:
            task = prog.add_task("Running presets", total=len(presets))
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                future_map = { ex.submit(_exec_capture_task, cmd, dry_run): k for k, cmd in preset_cmds.items() }
                for fut in as_completed(future_map):
                    k = future_map[fut]
                    try:
                        outputs[k] = fut.result()
                    except Exception as e:
                        outputs[k] = f"\n[!] Error preset {k}: {e}\n"
                    prog.advance(task, 1)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            future_map = { ex.submit(_exec_capture_task, cmd, dry_run): k for k, cmd in preset_cmds.items() }
            for fut in as_completed(future_map):
                k = future_map[fut]
                try: outputs[k] = fut.result()
                except Exception as e: outputs[k] = f"\n[!] Error preset {k}: {e}\n"
    return outputs

# ---------- Flows ----------
def quick_mode_flow(targets_list: List[str], use_sudo: bool, stream: bool,
                    vuln_mode: str, max_workers: int, dry_run: bool=False):
    label_targets=" ".join(targets_list)
    ping_args=build_nmap_args("ping", targets_list, use_sudo=use_sudo)
    ping_raw = run_stream(ping_args, dry_run=dry_run) if (stream and len(targets_list)==1) else run_capture(ping_args, dry_run=dry_run)
    hosts=[]
    for line in ping_raw.splitlines():
        m=re.search(r'Nmap scan report for (?:.+\()?(?P<ip>\d+\.\d+\.\d+\.\d+)\)?', line)
        if m: hosts.append(m.group("ip"))
    hosts=list(dict.fromkeys(hosts))
    print(Fore.YELLOW + f"[+] Quick-mode: {len(hosts)} live host(s): {hosts}")

    findings_all=[]; stats_agg={"OPEN":0,"CLOSED":0,"FILTERED":0,"VULNERABLE":0,"INFO":0}
    full_raw = ping_raw
    if hosts:
        outs = parallel_run_targets("top100", hosts, "", use_sudo, "", max_workers=max_workers, dry_run=dry_run)
        for h, raw in outs.items():
            full_raw += f"\n\n===== {h} =====\n{raw}"
            fnd, st = simple_analyze(raw, vuln_mode)
            findings_all.extend(fnd)
            for k in stats_agg: stats_agg[k]+=st.get(k,0)
    ai_rep=ai_assist_analysis(full_raw, vuln_mode)
    return label_targets, full_raw, findings_all, stats_agg, ai_rep

def run_all_scans_seq(targets_list: List[str], use_sudo: bool, stream: bool,
                      vuln_mode: str, max_workers: int, dry_run: bool=False):
    label=" ".join(targets_list)
    wildcard_domains=[d for d in targets_list if is_domain(d) and dns_wildcard_check(d)]
    if wildcard_domains:
        print(Fore.YELLOW + "Note: DNS wildcard suspected on: " + ", ".join(wildcard_domains))

    outs = parallel_run_presets(ALL_SCANS_SEQ, targets_list, use_sudo, max_workers=max_workers, dry_run=dry_run)
    grand_raw=""; findings_all=[]; stats_agg={"OPEN":0,"CLOSED":0,"FILTERED":0,"VULNERABLE":0,"INFO":0}
    for key in ALL_SCANS_SEQ:
        raw = outs.get(key,"")
        grand_raw += f"\n\n===== {key} =====\n{raw}"
        fnd, st = simple_analyze(raw, vuln_mode)
        findings_all.extend(fnd)
        for k in stats_agg: stats_agg[k]+=st.get(k,0)
    ai_rep=ai_assist_analysis(grand_raw, vuln_mode)
    if wildcard_domains:
        ai_rep["overall"]["notes"].append("DNS wildcard suspected on: " + ", ".join(wildcard_domains))
    return label, grand_raw, findings_all, stats_agg, ai_rep

def batch_or_combined_run(choice: str, targets_list: List[str], custom_ports: str, use_sudo: bool,
                          extra_opts: str, stream: bool, per_target_reports: bool, vuln_mode: str,
                          max_workers: int, dry_run: bool=False):
    wildcard_note_targets=[t for t in targets_list if choice=="dns_enum" and is_domain(t) and dns_wildcard_check(t)]
    if per_target_reports:
        outs = parallel_run_targets(choice, targets_list, custom_ports, use_sudo, extra_opts, max_workers=max_workers, dry_run=dry_run)
        grand_raw=""; findings_all=[]; stats_agg={"OPEN":0,"CLOSED":0,"FILTERED":0,"VULNERABLE":0,"INFO":0}
        for t in targets_list:
            raw = outs.get(t,"")
            fnd, st = simple_analyze(raw, vuln_mode)
            ai_rep_t = ai_assist_analysis(raw, vuln_mode)
            if t in wildcard_note_targets:
                ai_rep_t["overall"]["notes"].append(f"DNS wildcard suspected on: {t}")
            # per target save here:
            save_reports(t, choice, raw, fnd, st, ai_rep=ai_rep_t,
                         save_txt=DEFAULT_SAVE_TXT, save_json=DEFAULT_SAVE_JSON, save_html=DEFAULT_SAVE_HTML)
            grand_raw += f"\n\n===== {t} =====\n" + raw
            findings_all.extend(fnd)
            for k in stats_agg: stats_agg[k]+=st.get(k,0)
        ai_rep_all = ai_assist_analysis(grand_raw, vuln_mode)
        if wildcard_note_targets:
            ai_rep_all["overall"]["notes"].append("DNS wildcard suspected on: " + ", ".join(wildcard_note_targets))
        return ", ".join(targets_list), grand_raw, findings_all, stats_agg, ai_rep_all
    else:
        cmd=build_nmap_args(choice, targets_list, custom_ports, use_sudo, extra_opts)
        raw = run_stream(cmd, dry_run=dry_run) if (stream and len(targets_list)==1) else run_capture(cmd, dry_run=dry_run)
        fnd, st = simple_analyze(raw, vuln_mode)
        ai_rep=ai_assist_analysis(raw, vuln_mode)
        if wildcard_note_targets:
            ai_rep["overall"]["notes"].append("DNS wildcard suspected on: " + ", ".join(wildcard_note_targets))
        return " ".join(targets_list), raw, fnd, st, ai_rep

# ---------- Interactive UI ----------
def interactive_menu(global_out_dir: Optional[str]=None):
    while True:
        clear()
        print(render_banner())
        print(Fore.YELLOW + "Tips: 'all' = curated multi-scan (parallel) • 'm' = Quick-Mode • Use --save-html for pretty report\n")

        keys=list(SCAN_PRESETS.keys())
        for i,k in enumerate(keys,1):
            print(Fore.CYAN + f" {i:2d}. {k:16s} -> {SCAN_PRESETS[k]}")
        print(Fore.CYAN + f" {len(keys)+1:2d}. all (curated multi-scan, parallel)")
        print(Fore.YELLOW + "\nOptions: [q] Quit   [m] Quick-Mode (discovery + top100 + AI)\n")

        choice=input(Fore.YELLOW + "Enter choice/name/option: ").strip()
        if not choice: continue
        if choice.lower() in ("q","quit","exit"):
            print(Fore.YELLOW + "Bye."); break

        report_scan_key = "quick"  # default if we go quick

        if choice.lower() in ("m","quick","quick-mode"):
            targets_in=input(Fore.YELLOW + "Targets (IPs/domains/CIDR or @file): ").strip()
            targets_list=parse_targets(targets_in)
            if not targets_list: print(Fore.RED + "No targets parsed."); input("Enter..."); continue
            use_sudo=(input(Fore.YELLOW + "Use sudo? (y/n) [y]: ").strip().lower() or 'y')=='y'
            stream=(input(Fore.YELLOW + "Stream single-host live? (y/n) [n]: ").strip().lower() or 'n')=='y'
            mode_sel=(input(Fore.YELLOW + "Vuln mode [1=Strict,2=Relaxed] [1]: ").strip() or '1')
            workers_in=(input(Fore.YELLOW + "Max workers [default 4,max 50]: ").strip() or '4')
            dry_run=(input(Fore.YELLOW + "Dry-run? (print commands only) (y/n) [n]: ").strip().lower() or 'n')=='y'
            try:
                mw=int(workers_in); max_workers= max(1, min(50, mw))
            except:
                max_workers=4
            vuln_mode="relaxed" if mode_sel=="2" else "strict"
            label, raw, findings, stats, ai_rep = quick_mode_flow(targets_list, use_sudo, stream, vuln_mode, max_workers, dry_run=dry_run)
        else:
            try:
                idx=int(choice)
                if 1<=idx<=len(SCAN_PRESETS):
                    choice_key=list(SCAN_PRESETS.keys())[idx-1]
                elif idx==len(SCAN_PRESETS)+1:
                    choice_key="all_sequence"
                else:
                    print(Fore.RED+"Invalid number."); input("Enter..."); continue
            except ValueError:
                choice_key=choice

            report_scan_key = "all" if choice_key in ("all_sequence","all","all-scans") else choice_key

            targets_in=input(Fore.YELLOW + "Targets (IPs/domains/CIDR or @file): ").strip()
            targets_list=parse_targets(targets_in)
            if not targets_list: print(Fore.RED + "No targets parsed."); input("Enter..."); continue
            use_sudo=(input(Fore.YELLOW + "Use sudo? (y/n) [y]: ").strip().lower() or 'y')=='y'
            stream=(input(Fore.YELLOW + "Stream live? (y/n) [n]: ").strip().lower() or 'n')=='y'
            custom_ports=""
            extra_opts=""
            per_target=True
            if choice_key not in ("all_sequence","all","all-scans"):
                custom_ports=input(Fore.YELLOW + "Custom ports (e.g. 22,80-90) or Enter: ").strip()
                extra_opts=input(Fore.YELLOW + "Extra nmap options (limited whitelist) or Enter: ").strip()
                per_target=(input(Fore.YELLOW + "Per-target reports? (y/n) [y]: ").strip().lower() or 'y')=='y'
            mode_sel=(input(Fore.YELLOW + "Vuln mode [1=Strict,2=Relaxed] [1]: ").strip() or '1')
            workers_in=(input(Fore.YELLOW + "Max workers [default 4,max 50]: ").strip() or '4')
            dry_run=(input(Fore.YELLOW + "Dry-run? (y/n) [n]: ").strip().lower() or 'n')=='y'
            try:
                mw=int(workers_in); max_workers= max(1, min(50, mw))
            except:
                max_workers=4
            vuln_mode="relaxed" if mode_sel=="2" else "strict"

            if choice_key in ("all_sequence","all","all-scans"):
                label, raw, findings, stats, ai_rep = run_all_scans_seq(targets_list, use_sudo, stream, vuln_mode, max_workers, dry_run=dry_run)
            else:
                label, raw, findings, stats, ai_rep = batch_or_combined_run(
                    choice_key, targets_list, custom_ports, use_sudo, extra_opts, stream, per_target, vuln_mode, max_workers, dry_run=dry_run
                )

        print_ai_summary(ai_rep)
        print(Fore.WHITE + "\n--- OVERALL STATS ---")
        for k,v in stats.items(): print(Fore.CYAN + f"{k}: {v}")
        save_reports(label, report_scan_key, raw, findings, stats,
                     ai_rep=ai_rep, save_txt=DEFAULT_SAVE_TXT, save_json=DEFAULT_SAVE_JSON, save_html=DEFAULT_SAVE_HTML,
                     out_dir=global_out_dir)
        input("Press Enter to continue...")

# ---------- CLI ----------
def cli_main(args: argparse.Namespace) -> None:
    global REPORT_DIR
    check_prereqs()
    if args.list_scans:
        print(f"Total presets: {len(SCAN_PRESETS)}")
        for k,v in SCAN_PRESETS.items():
            print(f"{k:18s} -> {v}")
        return
    if args.version:
        print(f"Ai-NmapX v{__version__}")
        return

    if args.output_dir:
        REPORT_DIR = args.output_dir

    targets_list=parse_targets(args.targets)
    if not targets_list:
        print(Fore.RED + "No targets parsed."); sys.exit(1)

    vuln_mode="relaxed" if args.vuln_mode=="relaxed" else "strict"
    stream=args.stream; use_sudo=args.sudo
    # clamp workers
    mw = args.max_workers or 4
    max_workers = max(1, min(50, mw))
    if mw != max_workers:
        print(Fore.YELLOW + f"[~] max-workers clamped to {max_workers}")

    dry_run = args.dry_run

    if args.scan in ("all","all-scans"):
        label, raw, findings, stats, ai_rep = run_all_scans_seq(targets_list, use_sudo, stream, vuln_mode, max_workers, dry_run=dry_run)
        scan_key_for_report = "all"
    elif args.scan=="quick":
        label, raw, findings, stats, ai_rep = quick_mode_flow(targets_list, use_sudo, stream, vuln_mode, max_workers, dry_run=dry_run)
        scan_key_for_report = "quick"
    else:
        label, raw, findings, stats, ai_rep = batch_or_combined_run(
            args.scan, targets_list, args.ports or "", use_sudo, args.extra or "", stream,
            args.per_target, vuln_mode, max_workers, dry_run=dry_run
        )
        scan_key_for_report = args.scan

    print_ai_summary(ai_rep)

    # ---- SAVE FLAG LOGIC ----
    save_txt  = DEFAULT_SAVE_TXT  if not args.no_save_txt  else False
    save_json = DEFAULT_SAVE_JSON if not args.no_save_json else False
    save_html = args.save_html if args.save_html is not None else DEFAULT_SAVE_HTML

    save_reports(label, scan_key_for_report, raw, findings, stats, ai_rep=ai_rep,
                 save_txt=save_txt, save_json=save_json, save_html=save_html,
                 out_dir=args.output_dir)

def build_argparser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(description=f"Ai-NmapX v{__version__} — Parallel & Rich TUI Nmap wrapper with AI (secure exec + patched heuristics)")
    p.add_argument("--targets","-t", type=str, default="", help="Targets (comma/space) or @file")
    p.add_argument("--scan","-s", type=str, default="quick",
                   help=f"Preset or raw nmap args. Presets: {', '.join(SCAN_PRESETS.keys())} | 'all' | 'quick'")
    p.add_argument("--ports","-p", type=str, help="Custom ports (e.g. 22,80-90)")
    p.add_argument("--extra","-e", type=str, help="Extra nmap options (whitelisted only)")
    p.add_argument("--sudo", action="store_true", help="Use sudo if not root")
    p.add_argument("--stream", action="store_true", help="Stream live output (parallel steps use capture)")
    p.add_argument("--per-target", action="store_true", help="Run per-target with individual reports")
    p.add_argument("--vuln-mode", choices=("strict","relaxed"), default="strict", help="Vuln sensitivity")
    # Report toggles (override defaults which are HTML only)
    p.add_argument("--save-html", dest="save_html", action="store_true", help="Also/only save HTML (default True)")
    p.add_argument("--no-save-html", dest="save_html", action="store_false", help="Disable HTML save")
    p.set_defaults(save_html=None)  # None = use default
    p.add_argument("--no-save-txt", dest="no_save_txt", action="store_true", help="Skip TXT")
    p.add_argument("--no-save-json", dest="no_save_json", action="store_true", help="Skip JSON")
    p.add_argument("--interactive","-i", action="store_true", help="Interactive menu")
    p.add_argument("--list-scans", action="store_true", help="List presets and exit")
    p.add_argument("--max-workers", type=int, default=4, help="Parallel threads (default 4, max 50)")
    p.add_argument("--dry-run", action="store_true", help="Only print nmap commands, do not execute")
    p.add_argument("--output-dir", type=str, default=None, help="Directory for reports (default ./reports)")
    p.add_argument("--version","-v", action="store_true", help="Show version and exit")
    return p

def main():
    parser=build_argparser()
    args=parser.parse_args()
    if args.interactive or not args.targets:
        check_prereqs()
        if args.output_dir:
            interactive_menu(global_out_dir=args.output_dir)
        else:
            interactive_menu()
    else:
        cli_main(args)

if __name__ == "__main__":
    main()
