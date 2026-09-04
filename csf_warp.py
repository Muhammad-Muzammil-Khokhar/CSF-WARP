#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSF-WARP
Cyber Squad Forge -- Weaponized Assessment & Recon Platform
=============================================================

A menu-driven orchestration console for Kali Linux that catalogs, launches
and reports on offensive security tools across twelve engagement phases:
Reconnaissance, Vulnerability Scanning, Network-Based Attacks, Password &
Brute-Force Attacks, Mobile Security, Reverse Engineering, Exploitation,
Post-Exploitation, Wireless Attacks, Social Engineering & Phishing,
Web App Penetration Testing, and Reporting & Documentation.

CSF-WARP does NOT reimplement or bundle any offensive capability itself.
It is a wrapper: it checks whether the real, upstream tool is installed on
the host, builds the command line the operator asked for, executes it
(or hands the terminal to it, or launches it, depending on the tool's
nature), captures the outcome, and rolls everything up into a polished
HTML report at the end of the engagement.

Legal / ethical use
--------------------
This tool is built for authorized penetration testing, red-teaming and
security education ONLY. Every session requires the operator to confirm
they hold written authorization before any tool can be executed, and
every high-risk tool requires a second, explicit confirmation. Running
these tools against systems you do not own or do not have documented
permission to test is illegal in most jurisdictions and is not condoned
by Cyber Squad Forge.

Author: Cyber Squad Forge
"""

import argparse
import html
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich import box
except ImportError:
    sys.stderr.write(
        "[!] Missing dependency 'rich'.\n"
        "    Install it with: pip3 install rich --break-system-packages\n"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
VERSION = "1.0.0"
CODENAME = "Obsidian Falcon"
AUTHOR = "Cyber Squad Forge"

console = Console()

# ---------------------------------------------------------------------------
# Paths & logging
# ---------------------------------------------------------------------------
BASE_DIR = Path.home() / "CSF-WARP"
SESSIONS_DIR = BASE_DIR / "sessions"
LOG_DIR = BASE_DIR / "logs"
for _d in (BASE_DIR, SESSIONS_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"csf_warp_{RUN_ID}.log"

logger = logging.getLogger("csf_warp")
logger.setLevel(logging.DEBUG)
_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
)
logger.addHandler(_file_handler)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
class LaunchMode(Enum):
    CLI = "cli"                  # blocking subprocess, output captured
    INTERACTIVE = "interactive"  # terminal handed to the tool (e.g. msfconsole)
    GUI = "gui"                  # detached graphical application
    SERVICE = "service"          # a daemon/platform CSF-WARP can start and point you at
    LIBRARY = "library"          # a scripting library, not a standalone executable
    REFERENCE = "reference"      # documentation / not runnable from here


class ToolStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    NOT_INSTALLED = "NOT_INSTALLED"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"
    LAUNCHED = "LAUNCHED"
    INFO = "INFO"


STATUS_COLORS = {
    ToolStatus.SUCCESS: "green",
    ToolStatus.FAILED: "red",
    ToolStatus.NOT_INSTALLED: "grey62",
    ToolStatus.TIMEOUT: "orange3",
    ToolStatus.SKIPPED: "yellow",
    ToolStatus.LAUNCHED: "cyan",
    ToolStatus.INFO: "magenta",
}


@dataclass
class ToolDefinition:
    name: str
    binary: str
    category: str
    description: str
    mode: LaunchMode
    cmd_template: List[str] = field(default_factory=list)  # tokens; "{target}" is replaced
    default_args: str = ""
    needs_target: bool = True
    high_risk: bool = False
    notes: str = ""


@dataclass
class ToolResult:
    tool: str
    category: str
    command: str
    status: ToolStatus
    started_at: str
    duration_s: float
    output: str = ""
    target: str = ""


def td(name, binary, description, mode, cmd_template=None, default_args="",
       needs_target=True, high_risk=False, notes=""):
    return ToolDefinition(
        name=name, binary=binary, category="", description=description, mode=mode,
        cmd_template=cmd_template or [], default_args=default_args,
        needs_target=needs_target, high_risk=high_risk, notes=notes,
    )


# ---------------------------------------------------------------------------
# Tool catalog
# ---------------------------------------------------------------------------
CATEGORIES = [
    "Reconnaissance",
    "Vulnerability Scanning",
    "Network-Based Attacks",
    "Password & Brute-Force Attacks",
    "Mobile Security",
    "Reverse Engineering",
    "Exploitation",
    "Post-Exploitation",
    "Wireless Attacks",
    "Social Engineering & Phishing",
    "Web App Penetration Testing",
    "Reporting & Documentation",
]

TOOL_CATALOG: Dict[str, List[ToolDefinition]] = {
    "Reconnaissance": [
        td("Recon-ng", "recon-ng",
           "Full-featured web reconnaissance framework with modules for OSINT collection.",
           LaunchMode.INTERACTIVE, needs_target=False,
           notes="Inside the shell: 'workspaces create <name>' then 'marketplace install all'."),
        td("theHarvester", "theHarvester",
           "Gathers emails, subdomains, hosts and employee names from public sources.",
           LaunchMode.CLI, cmd_template=["-d", "{target}", "-b", "all"]),
        td("Nmap", "nmap",
           "Network mapper for host discovery and service/version detection.",
           LaunchMode.CLI, cmd_template=["-sV", "-Pn", "{target}"]),
        td("Zenmap", "zenmap",
           "Official Nmap graphical front-end.",
           LaunchMode.GUI, needs_target=False),
        td("DNSRecon", "dnsrecon",
           "DNS enumeration and zone-transfer testing.",
           LaunchMode.CLI, cmd_template=["-d", "{target}"]),
        td("Mitaka", "mitaka",
           "Browser extension for one-click OSINT/IOC lookups.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="Installed as a Chrome/Firefox extension, not a CLI binary. Right-click any "
                 "IOC in the browser to pivot across OSINT search engines."),
        td("Maltego", "maltego",
           "Link-analysis and OSINT graphing platform.",
           LaunchMode.GUI, needs_target=False),
        td("Fierce", "fierce",
           "Domain scanner that locates non-contiguous IP space via DNS.",
           LaunchMode.CLI, cmd_template=["--domain", "{target}"]),
        td("SpiderFoot", "spiderfoot",
           "Automated OSINT reconnaissance across 200+ data sources.",
           LaunchMode.CLI, cmd_template=["-s", "{target}"],
           notes="If 'spiderfoot' isn't on PATH, run 'python3 sf.py -l 127.0.0.1:5001' from "
                 "the install directory for the web UI instead."),
        td("Masscan", "masscan",
           "Internet-scale asynchronous port scanner.",
           LaunchMode.CLI, cmd_template=["{target}", "-p1-1000", "--rate", "1000"],
           high_risk=True,
           notes="Requires root/CAP_NET_RAW. High packet rates can be disruptive -- confirm "
                 "scope and rate limits with the client first."),
        td("ZMap", "zmap",
           "Single-packet, internet-wide network scanner.",
           LaunchMode.CLI, cmd_template=["-p", "80", "{target}"], high_risk=True),
    ],
    "Vulnerability Scanning": [
        td("OpenVAS / GVM", "gvm-cli",
           "Full vulnerability management platform (Greenbone Vulnerability Management).",
           LaunchMode.SERVICE, needs_target=False,
           notes="Start with 'gvm-start', then browse https://127.0.0.1:9392."),
        td("w3af", "w3af_console",
           "Web application attack and audit framework.",
           LaunchMode.INTERACTIVE, needs_target=False),
        td("Nikto", "nikto",
           "Web server scanner for dangerous files, outdated software and misconfigurations.",
           LaunchMode.CLI, cmd_template=["-h", "{target}"]),
        td("Vuls", "vuls",
           "Agentless vulnerability scanner for Linux/FreeBSD servers.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Requires a config.toml. Run 'vuls configtest' then 'vuls scan' from the "
                 "configured working directory."),
        td("Nessus", "nessuscli",
           "Commercial vulnerability scanner by Tenable.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Start with 'systemctl start nessusd', then browse https://127.0.0.1:8834."),
    ],
    "Network-Based Attacks": [
        td("Wireshark", "wireshark",
           "Deep-dive network protocol analyzer with a graphical packet browser.",
           LaunchMode.GUI, needs_target=False,
           notes="For CLI capture, use the bundled 'tshark' binary instead."),
        td("Ettercap", "ettercap",
           "Suite for man-in-the-middle attacks on LANs (ARP poisoning, sniffing, filtering).",
           LaunchMode.INTERACTIVE, cmd_template=["-T", "-q"], needs_target=False,
           high_risk=True,
           notes="Supply interface/target flags via extra args, e.g. "
                 "'-i eth0 -M arp:remote /192.168.1.1// /192.168.1.50//'."),
        td("ArpSpoof", "arpspoof",
           "Redirects LAN traffic by forging ARP replies (part of dsniff).",
           LaunchMode.CLI, cmd_template=["{target}"], high_risk=True,
           notes="Typically needs '-i <iface> -t <victim>' in extra args; target is the host "
                 "to impersonate to."),
        td("NetCat", "nc",
           "Reads/writes raw TCP/UDP connections -- the network 'Swiss army knife'.",
           LaunchMode.CLI, cmd_template=["-v", "{target}"],
           notes="Add the port and flags via extra args as appropriate."),
        td("dSniff", "dsniff",
           "Passive network sniffer that captures credentials from clear-text protocols.",
           LaunchMode.CLI, needs_target=False, high_risk=True,
           notes="Supply the interface via extra args, e.g. '-i eth0'."),
        td("Scapy", "scapy",
           "Interactive packet manipulation library/shell for crafting and sending packets.",
           LaunchMode.INTERACTIVE, needs_target=False),
        td("hping3", "hping3",
           "Custom TCP/IP packet assembler for scanning, firewall testing and packet crafting.",
           LaunchMode.CLI, cmd_template=["{target}"], high_risk=True),
        td("Yersinia", "yersinia",
           "Layer-2 attack framework targeting STP, CDP, DHCP, DTP and other protocols.",
           LaunchMode.INTERACTIVE, cmd_template=["-I"], needs_target=False, high_risk=True),
    ],
    "Password & Brute-Force Attacks": [
        td("John the Ripper", "john",
           "Offline password hash cracker supporting numerous hash formats.",
           LaunchMode.CLI, cmd_template=["{target}"],
           notes="Target is the path to a hash/password file."),
        td("Hashcat", "hashcat",
           "GPU-accelerated password recovery supporting hundreds of hash types.",
           LaunchMode.CLI, cmd_template=["{target}"],
           notes="Target is the hash file; supply mode/attack/wordlist via extra args, e.g. "
                 "'-m 0 -a 0 wordlist.txt'."),
        td("Crunch", "crunch",
           "Wordlist generator that creates permutations from a character set.",
           LaunchMode.CLI, needs_target=False,
           notes="Provide '<min> <max> [charset] -o out.txt' via extra args."),
        td("Hydra", "hydra",
           "Fast network login cracker supporting dozens of protocols.",
           LaunchMode.CLI, cmd_template=["{target}"], high_risk=True,
           notes="Supply '-l user -P wordlist.txt <service>' via extra args."),
        td("Medusa", "medusa",
           "Parallel, modular login brute-forcer.",
           LaunchMode.CLI, cmd_template=["-h", "{target}"], high_risk=True,
           notes="Supply '-u user -P wordlist.txt -M <module>' via extra args."),
        td("RainbowCrack", "rcrack",
           "Precomputed rainbow-table based hash cracker.",
           LaunchMode.CLI, cmd_template=["{target}"],
           notes="Target is the rainbow-table directory; supply '-h <hash>' via extra args."),
        td("CeWL", "cewl",
           "Custom wordlist generator that spiders a website for likely passwords.",
           LaunchMode.CLI, cmd_template=["{target}"]),
        td("Patator", "patator",
           "Modular multi-purpose brute-forcer covering many protocols in one tool.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True,
           notes="Supply the full module invocation via extra args, e.g. "
                 "'ssh_login host=10.0.0.1 user=root password=FILE0 0=pass.txt'."),
        td("Ophcrack", "ophcrack",
           "Windows LM/NTLM password cracker using rainbow tables (GUI-first).",
           LaunchMode.GUI, needs_target=False),
        td("pydictor", "pydictor",
           "Flexible Python wordlist/dictionary generator for targeted password lists.",
           LaunchMode.CLI, needs_target=False,
           notes="Supply generation flags via extra args, e.g. '--len 6 8 -o out.txt'. Some "
                 "installs expose this as 'pydictor.py'."),
        td("Kraken", "kraken",
           "Distributed password-cracking coordination tool.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="Not part of standard Kali repositories -- build it from its source "
                 "repository, then run its coordinator/worker components manually."),
    ],
    "Mobile Security": [
        td("Drozer", "drozer",
           "Android security assessment framework for testing apps/devices via an agent.",
           LaunchMode.INTERACTIVE, cmd_template=["console", "connect"], needs_target=False),
        td("Androguard", "androguard",
           "Reverse engineering and static analysis toolkit for Android APKs.",
           LaunchMode.CLI, cmd_template=["analyze", "{target}"],
           notes="Target is the path to an APK file."),
        td("Frida", "frida",
           "Dynamic instrumentation toolkit for hooking functions in running processes/apps.",
           LaunchMode.CLI, cmd_template=["-U", "{target}"],
           notes="Target is the app identifier/spawn name; add '-l script.js' via extra args."),
        td("MobSF", "docker",
           "Automated static/dynamic mobile app (Android/iOS) security analysis platform.",
           LaunchMode.SERVICE,
           cmd_template=["run", "-p", "8000:8000", "mobsf/mobile-security-framework-mobsf"],
           needs_target=False,
           notes="Runs as a Docker container; browse http://127.0.0.1:8000 once started."),
        td("MASTG", "mastg",
           "OWASP Mobile Application Security Testing Guide -- reference methodology.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="A documentation project, not an executable tool. Use it to structure test "
                 "cases while running the other mobile tools in this menu."),
        td("NetHunter", "nethunter",
           "Kali NetHunter -- Android penetration testing platform/ROM and companion app.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="Runs on a rooted Android device as its own app/ROM, not as a binary on this "
                 "host. Deploy via the NetHunter installer on the target device."),
        td("Android Tamer", "android-tamer",
           "Dedicated Android security distribution bundling mobile testing tools.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="A full Linux distribution rather than a single binary."),
        td("Apktool", "apktool",
           "Decodes/rebuilds Android APK resources and smali code.",
           LaunchMode.CLI, cmd_template=["d", "{target}"],
           notes="Target is the APK path; 'd' decodes -- pass 'b <dir>' via extra args to "
                 "rebuild instead."),
        td("Quark Engine", "quark",
           "Scores APKs against known malicious/behavioral rules for rapid triage.",
           LaunchMode.CLI, cmd_template=["-a", "{target}", "-s"],
           notes="Target is the APK path."),
        td("bettercap", "bettercap",
           "Swiss-army-knife for network, Wi-Fi and BLE reconnaissance and MITM attacks.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True,
           notes="Supply interface/caplet via extra args, e.g. '-iface wlan0'."),
    ],
    "Reverse Engineering": [
        td("Radare2", "r2",
           "Command-line framework for disassembling, debugging and analyzing binaries.",
           LaunchMode.INTERACTIVE, cmd_template=["{target}"],
           notes="Target is the binary to analyze."),
        td("Ghidra", "ghidraRun",
           "NSA-developed interactive software reverse engineering suite with a decompiler.",
           LaunchMode.GUI, needs_target=False),
        td("angr", "angr",
           "Python binary analysis library for symbolic execution and CFG recovery.",
           LaunchMode.LIBRARY, needs_target=False,
           notes="Used from Python: import angr; p = angr.Project('/path/binary'); "
                 "p.analyses.CFGFast()."),
    ],
    "Exploitation": [
        td("Metasploit", "msfconsole",
           "The industry-standard exploitation and payload framework.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("Exploit Pack", "exploitpack",
           "Java-based exploit development and delivery framework.",
           LaunchMode.GUI, needs_target=False, high_risk=True),
        td("SQL Ninja", "sqlninja",
           "Microsoft SQL Server injection and takeover tool.",
           LaunchMode.CLI, needs_target=False, high_risk=True,
           notes="Supply '-f config.cfg -m t' via extra args."),
        td("PTF", "ptf",
           "Pentesters Framework -- modular installer that fetches and organizes tools.",
           LaunchMode.INTERACTIVE, needs_target=False),
        td("jSQL Injection", "jsql",
           "Java GUI tool for automated SQL injection.",
           LaunchMode.GUI, needs_target=False, high_risk=True),
        td("sqlmap", "sqlmap",
           "Automated SQL injection detection and database takeover tool.",
           LaunchMode.CLI, cmd_template=["-u", "{target}", "--batch"], high_risk=True),
        td("Armitage", "armitage",
           "Graphical cyber-attack management front-end for Metasploit.",
           LaunchMode.GUI, needs_target=False, high_risk=True),
        td("BeEF", "beef-xss",
           "Browser Exploitation Framework -- hooks browsers for client-side attacks.",
           LaunchMode.SERVICE, needs_target=False, high_risk=True,
           notes="Starts the hook server; browse http://127.0.0.1:3000/ui/panel (default "
                 "creds are in beef's config.yaml)."),
        td("RouterSploit", "rsf",
           "Exploitation framework focused on embedded/router devices.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("ShellNoob", "shellnoob",
           "Shellcode writing/debugging toolkit that converts between asm/hex/C/etc.",
           LaunchMode.CLI, needs_target=False,
           notes="Supply mode flags via extra args, e.g. '--asm-to-opcode'."),
        td("ysoserial", "java",
           "Generates payloads exploiting unsafe Java object deserialization.",
           LaunchMode.CLI, cmd_template=["-jar", "ysoserial.jar"], needs_target=False,
           high_risk=True,
           notes="Pass the gadget chain/command via extra args, e.g. 'CommonsCollections6 id'. "
                 "Requires ysoserial.jar in the working directory."),
        td("Ropper", "ropper",
           "Finds ROP/JOP gadgets and builds chains in binaries.",
           LaunchMode.CLI, cmd_template=["-f", "{target}"],
           notes="Target is the binary to search."),
        td("Commix", "commix",
           "Automated OS command injection detection and exploitation.",
           LaunchMode.CLI, cmd_template=["--url", "{target}"], high_risk=True),
        td("SearchSploit / Exploit-DB", "searchsploit",
           "Offline command-line search interface to the Exploit-DB archive.",
           LaunchMode.CLI, cmd_template=["{target}"],
           notes="Target is a search term, e.g. product/version."),
        td("Pwntools", "pwntools",
           "Python CTF/exploit-development library for crafting exploits.",
           LaunchMode.LIBRARY, needs_target=False,
           notes="Used from Python: from pwn import *; io = process('./binary')."),
        td("XSSer", "xsser",
           "Automated cross-site scripting detection and exploitation framework.",
           LaunchMode.CLI, cmd_template=["-u", "{target}"], high_risk=True),
    ],
    "Post-Exploitation": [
        td("Empire", "powershell-empire",
           "Post-exploitation C2 framework for Windows/Linux/macOS agents.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True,
           notes="Some installs expose this as 'empire' instead."),
        td("Pupy", "pupysh",
           "Cross-platform, multi-function Python RAT and post-exploitation tool.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("BloodHound", "bloodhound",
           "Graphs Active Directory attack paths using SharpHound-collected data.",
           LaunchMode.GUI, needs_target=False,
           notes="Requires a running Neo4j database; start it with 'neo4j console' first."),
        td("Mimikatz", "mimikatz",
           "Extracts Windows credentials, tickets and hashes from LSASS memory.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="A native Windows tool -- it does not run on Kali/Linux. Deploy and execute "
                 "it on an authorized Windows target, e.g. via a Metasploit/Empire session."),
        td("Dnscat2", "dnscat2",
           "Command-and-control channel tunneled entirely over DNS queries.",
           LaunchMode.SERVICE, needs_target=False, high_risk=True,
           notes="Runs the Ruby server component; start the matching client on the target."),
        td("Koadic", "koadic",
           "Windows post-exploitation C2 that uses JScript/VBScript stagers.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("Meterpreter", "msfconsole",
           "Metasploit's advanced in-memory post-exploitation payload/shell.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="Accessed as a session inside msfconsole after successful exploitation, not a "
                 "standalone binary. Use the Metasploit entry under Exploitation."),
        td("BeRoot", "beroot",
           "Privilege-escalation enumeration script for Windows/Linux/macOS.",
           LaunchMode.CLI, needs_target=False,
           notes="Some installs require invoking it as 'python3 beroot.py'."),
        td("Pwncat", "pwncat",
           "Post-exploitation platform providing an enhanced netcat-like shell handler.",
           LaunchMode.CLI, cmd_template=["{target}"], high_risk=True,
           notes="Some installs expose this as 'pwncat-cs'."),
    ],
    "Wireless Attacks": [
        td("Kismet", "kismet",
           "Wireless network detector, sniffer and intrusion-detection framework.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Starts the Kismet server; browse http://127.0.0.1:2501."),
        td("PixieWPS", "pixiewps",
           "Offline WPS pixie-dust attack tool for recovering WPS PINs.",
           LaunchMode.CLI, needs_target=False, high_risk=True,
           notes="Supply captured PKE/PKR/E-hash values via extra args."),
        td("Wifite", "wifite",
           "Automates auditing of nearby wireless networks (WEP/WPA/WPS).",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("Reaver", "reaver",
           "Brute-forces WPS PINs to recover WPA/WPA2 passphrases.",
           LaunchMode.CLI, cmd_template=["-b", "{target}"], high_risk=True,
           notes="Add '-i wlan0mon -vv' etc. via extra args."),
        td("Aircrack-ng", "aircrack-ng",
           "Suite for monitoring, attacking and cracking WEP/WPA-PSK captures.",
           LaunchMode.CLI, cmd_template=["{target}"], high_risk=True,
           notes="Target is a capture (.cap/.pcap) file; add '-w wordlist.txt' via extra args."),
        td("airgeddon", "airgeddon",
           "Menu-driven multi-tool for Wi-Fi auditing (WPS, handshake, Evil Twin).",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("WiFi-Pumpkin3", "wifipumpkin3",
           "Rogue-AP framework for Wi-Fi MITM and phishing.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
    ],
    "Social Engineering & Phishing": [
        td("SET", "setoolkit",
           "Social-Engineer Toolkit for phishing, cloned sites and payload delivery.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
        td("Gophish", "gophish",
           "Open-source phishing simulation and campaign management platform.",
           LaunchMode.SERVICE, needs_target=False, high_risk=True,
           notes="Starts the admin server; browse https://127.0.0.1:3333 (default creds are "
                 "printed on first run)."),
        td("King Phisher", "king-phisher",
           "Phishing campaign toolkit with a client/server architecture.",
           LaunchMode.SERVICE, needs_target=False, high_risk=True,
           notes="Start 'king-phisher-server' with a config, then connect via the "
                 "'king-phisher' client."),
        td("PhishX", "phishx",
           "Interactive credential-harvesting/phishing utility.",
           LaunchMode.INTERACTIVE, needs_target=False, high_risk=True),
    ],
    "Web App Penetration Testing": [
        td("Burp Suite", "burpsuite",
           "Industry-standard intercepting proxy and web app testing platform.",
           LaunchMode.GUI, needs_target=False),
        td("OWASP ZAP", "zaproxy",
           "Free intercepting proxy and automated web app vulnerability scanner.",
           LaunchMode.GUI, needs_target=False,
           notes="For headless/CI use, invoke 'zap-baseline.py' or ZAP's CLI mode instead."),
        td("Arachni", "arachni",
           "Modular web application security scanner framework.",
           LaunchMode.CLI, cmd_template=["{target}"]),
        td("Wfuzz", "wfuzz",
           "Web application fuzzer for parameters, forms and hidden content.",
           LaunchMode.CLI, cmd_template=["{target}"],
           notes="Add '-w wordlist.txt -c' etc. via extra args."),
        td("Skipfish", "skipfish",
           "Fast, recursive active web application reconnaissance scanner.",
           LaunchMode.CLI, cmd_template=["{target}"],
           notes="Add '-o outputdir' via extra args."),
    ],
    "Reporting & Documentation": [
        td("Dradis", "dradis",
           "Collaborative reporting platform that aggregates results from multiple tools.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Start the service, then browse https://127.0.0.1:3000."),
        td("Faraday", "faraday-server",
           "Collaborative pentest platform with a shared vulnerability database.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Browse http://127.0.0.1:5985 once the server is running."),
        td("Serpico", "serpico",
           "Rails-based tool for rapidly generating penetration test reports.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Browse https://127.0.0.1:3000 (or the configured port) once started."),
        td("DefectDojo", "defectdojo",
           "Application vulnerability management and correlation platform.",
           LaunchMode.REFERENCE, needs_target=False,
           notes="Typically deployed via Docker Compose: './dc-build.sh && ./dc-up.sh' from "
                 "the DefectDojo repo, then browse the configured URL."),
        td("MagicTree", "magictree",
           "Java GUI tool for aggregating and querying pentest data across tools.",
           LaunchMode.GUI, needs_target=False),
        td("Lair Framework", "lair",
           "Real-time collaborative data-sharing platform for pentest teams.",
           LaunchMode.SERVICE, needs_target=False,
           notes="Start 'lair-server'/'lair-api-server' per its install docs, then connect "
                 "the Lair client."),
    ],
}

# Stamp each tool with its category name (keeps the catalog above free of repetition/typos).
for _cat_name, _tools in TOOL_CATALOG.items():
    for _t in _tools:
        _t.category = _cat_name


# ---------------------------------------------------------------------------
# Command construction & execution
# ---------------------------------------------------------------------------
def build_command(tool: ToolDefinition, target: str, extra: str) -> List[str]:
    cmd = [tool.binary]
    for tok in tool.cmd_template:
        cmd.append(target if tok == "{target}" else tok)
    if extra:
        cmd.extend(shlex.split(extra))
    return cmd


class ToolRunner:
    """Resolves, executes and safely reports on a single ToolDefinition."""

    def __init__(self, raw_dir: Path):
        self.raw_dir = raw_dir

    def run(self, tool: ToolDefinition, target: str, extra: str, timeout: int) -> ToolResult:
        started_dt = datetime.now()
        ts_str = started_dt.strftime("%Y-%m-%d %H:%M:%S")
        t0 = time.time()

        if tool.mode in (LaunchMode.REFERENCE, LaunchMode.LIBRARY):
            logger.info(f"{tool.name}: reference/library entry viewed")
            return ToolResult(tool.name, tool.category, "(reference only)", ToolStatus.INFO,
                               ts_str, 0.0, tool.notes or tool.description, target)

        resolved = shutil.which(tool.binary)
        if not resolved:
            logger.warning(f"{tool.name}: '{tool.binary}' not found on PATH")
            msg = (f"'{tool.binary}' was not found on PATH. Install the package that "
                   f"provides it, or add it to PATH.")
            return ToolResult(tool.name, tool.category, tool.binary, ToolStatus.NOT_INSTALLED,
                               ts_str, 0.0, msg, target)

        cmd = build_command(tool, target, extra)
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        logger.info(f"Executing [{tool.category}] {tool.name}: {cmd_str}")

        try:
            if tool.mode == LaunchMode.GUI:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
                duration = time.time() - t0
                return ToolResult(tool.name, tool.category, cmd_str, ToolStatus.LAUNCHED,
                                   ts_str, duration,
                                   f"Launched '{tool.name}' as a detached graphical application.",
                                   target)

            if tool.mode == LaunchMode.SERVICE:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
                duration = time.time() - t0
                return ToolResult(tool.name, tool.category, cmd_str, ToolStatus.LAUNCHED,
                                   ts_str, duration,
                                   f"Started '{tool.name}' in the background. {tool.notes}",
                                   target)

            if tool.mode == LaunchMode.INTERACTIVE:
                console.print(
                    f"[bold yellow]Handing the terminal to {tool.name}. "
                    f"Exit it normally to return to CSF-WARP.[/]"
                )
                result = subprocess.run(cmd)
                duration = time.time() - t0
                status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.FAILED
                return ToolResult(tool.name, tool.category, cmd_str, status, ts_str, duration,
                                   f"Interactive session ended with exit code {result.returncode}.",
                                   target)

            # LaunchMode.CLI
            with console.status(f"[bold cyan]Running {tool.name}...[/]", spinner="dots"):
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            duration = time.time() - t0
            combined = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
            self._save_raw(tool.name, combined)
            status = ToolStatus.SUCCESS if result.returncode == 0 else ToolStatus.FAILED
            return ToolResult(tool.name, tool.category, cmd_str, status, ts_str, duration,
                               combined.strip(), target)

        except subprocess.TimeoutExpired:
            duration = time.time() - t0
            logger.error(f"{tool.name}: timed out after {timeout}s")
            return ToolResult(tool.name, tool.category, cmd_str, ToolStatus.TIMEOUT, ts_str,
                               duration, f"Execution exceeded the {timeout}s timeout and was "
                                         f"aborted.", target)
        except PermissionError as exc:
            duration = time.time() - t0
            logger.error(f"{tool.name}: permission error: {exc}")
            return ToolResult(tool.name, tool.category, cmd_str, ToolStatus.FAILED, ts_str,
                               duration, f"Permission denied: {exc}. Some tools require root "
                                         f"(sudo).", target)
        except FileNotFoundError as exc:
            duration = time.time() - t0
            logger.error(f"{tool.name}: {exc}")
            return ToolResult(tool.name, tool.category, cmd_str, ToolStatus.NOT_INSTALLED,
                               ts_str, duration, str(exc), target)
        except Exception as exc:  # noqa: BLE001 -- last-resort guard around 3rd-party tools
            duration = time.time() - t0
            logger.exception(f"{tool.name}: unexpected error")
            return ToolResult(tool.name, tool.category, cmd_str, ToolStatus.FAILED, ts_str,
                               duration, f"Unexpected error: {exc}", target)

    def _save_raw(self, tool_name: str, content: str) -> Path:
        safe = tool_name.replace(" ", "_").replace("/", "-")
        fname = f"{safe}_{datetime.now().strftime('%H%M%S')}.txt"
        path = self.raw_dir / fname
        try:
            path.write_text(content, encoding="utf-8")
        except Exception:
            logger.exception("Failed to write raw output file")
        return path


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------
_GLYPHS = {
    "C": [" ### ", "#   #", "#    ", "#   #", " ### "],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "F": ["#####", "#    ", "###  ", "#    ", "#    "],
    "-": ["     ", "     ", "#####", "     ", "     "],
    "W": ["#   #", "#   #", "# # #", "## ##", "#   #"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "P": ["#### ", "#   #", "#### ", "#    ", "#    "],
    " ": ["     ", "     ", "     ", "     ", "     "],
}


def build_ascii_banner(text: str) -> List[str]:
    rows = ["" for _ in range(5)]
    for ch in text.upper():
        glyph = _GLYPHS.get(ch, _GLYPHS[" "])
        for i in range(5):
            rows[i] += glyph[i] + " "
    return rows


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
REPORT_CSS = """
:root {
  --bg: #0b0f14; --panel: #121821; --panel2: #161e29; --text: #e6edf3; --muted: #8b98a5;
  --accent: #00e5ff; --accent2: #ff2e88; --ok: #2ecc71; --bad: #ff4d4f; --warn: #ffb020;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif; }
.hero { background: linear-gradient(135deg, #060a0f 0%, #0f1926 60%, #131c2e 100%);
        border-bottom:1px solid #1e2733; padding:48px 24px; }
.hero-inner { max-width:1100px; margin:0 auto; }
.brand { font-size:40px; font-weight:800; letter-spacing:1px; color:var(--text); }
.brand span { color:var(--accent); }
.brand-sub { color:var(--muted); margin-top:6px; font-size:14px; letter-spacing:0.5px;
             text-transform:uppercase; }
main { max-width:1100px; margin:0 auto; padding:32px 24px 80px; }
.section-title { margin-top:40px; margin-bottom:16px; font-size:20px; color:var(--accent);
                  border-left:4px solid var(--accent); padding-left:10px; }
.meta-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
             gap:12px; margin-top:-24px; }
.meta-box { background:var(--panel); border:1px solid #1e2733; border-radius:10px;
            padding:14px 16px; }
.meta-box span { display:block; color:var(--muted); font-size:11px; text-transform:uppercase;
                  letter-spacing:0.5px; margin-bottom:6px; }
.meta-box strong { font-size:15px; word-break:break-word; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; }
.card { background:var(--panel2); border:1px solid #1e2733; border-radius:10px; padding:18px;
        text-align:center; }
.card-num { font-size:28px; font-weight:800; color:var(--accent); }
.card-label { color:var(--muted); font-size:11px; text-transform:uppercase; margin-top:6px;
               letter-spacing:0.5px; }
table.cat-table { width:100%; border-collapse:collapse; background:var(--panel);
                   border:1px solid #1e2733; border-radius:10px; overflow:hidden; }
table.cat-table th, table.cat-table td { padding:12px 14px; text-align:left;
                                          border-bottom:1px solid #1e2733; font-size:14px; }
table.cat-table th { color:var(--muted); text-transform:uppercase; font-size:11px;
                      letter-spacing:0.5px; }
td.ok { color:var(--ok); font-weight:700; }
td.bad { color:var(--bad); font-weight:700; }
td.muted { color:var(--muted); }
.results { display:flex; flex-direction:column; gap:12px; }
.result-item { background:var(--panel); border:1px solid #1e2733; border-radius:10px;
               padding:14px 16px; }
.result-head { display:flex; flex-wrap:wrap; align-items:center; gap:10px; margin-bottom:8px; }
.rt-name { font-weight:700; }
.rt-cat { color:var(--muted); font-size:12px; }
.rt-time { color:var(--muted); font-size:12px; margin-left:auto; }
.rt-cmd { color:var(--muted); font-size:12px; margin-bottom:6px; overflow-x:auto; }
.rt-cmd code { color:#c9d6e3; }
.rt-output pre { background:#080b0f; border:1px solid #1e2733; border-radius:8px; padding:12px;
                  overflow-x:auto; font-size:12px; color:#c9d6e3; white-space:pre-wrap;
                  word-break:break-word; }
.rt-output summary { cursor:pointer; color:var(--accent); font-size:12px; }
.badge { display:inline-block; padding:3px 10px; border-radius:999px; font-size:11px;
         font-weight:700; text-transform:uppercase; letter-spacing:0.5px; }
.badge.success { background:rgba(46,204,113,0.15); color:var(--ok); border:1px solid var(--ok); }
.badge.failed { background:rgba(255,77,79,0.15); color:var(--bad); border:1px solid var(--bad); }
.badge.not_installed { background:rgba(139,152,165,0.15); color:var(--muted);
                        border:1px solid var(--muted); }
.badge.timeout { background:rgba(255,176,32,0.15); color:var(--warn); border:1px solid var(--warn); }
.badge.skipped { background:rgba(255,176,32,0.1); color:var(--warn); border:1px solid var(--warn); }
.badge.launched { background:rgba(0,229,255,0.15); color:var(--accent); border:1px solid var(--accent); }
.badge.info { background:rgba(255,46,136,0.15); color:var(--accent2); border:1px solid var(--accent2); }
footer { margin-top:60px; color:var(--muted); font-size:12px; border-top:1px solid #1e2733;
         padding-top:20px; }
"""


class ReportGenerator:
    def __init__(self, operator: str, scope: str, start_time: datetime, results: List[ToolResult]):
        self.operator = operator
        self.scope = scope or "Not specified"
        self.start_time = start_time
        self.end_time = datetime.now()
        self.results = results

    def _summary_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in ToolStatus}
        for r in self.results:
            counts[r.status.value] += 1
        return counts

    def _category_breakdown(self):
        cats: Dict[str, Dict[str, int]] = {}
        for r in self.results:
            c = cats.setdefault(r.category, {"total": 0, "success": 0, "failed": 0, "other": 0})
            c["total"] += 1
            if r.status == ToolStatus.SUCCESS:
                c["success"] += 1
            elif r.status in (ToolStatus.FAILED, ToolStatus.TIMEOUT):
                c["failed"] += 1
            else:
                c["other"] += 1
        return cats

    def build_html(self) -> str:
        counts = self._summary_counts()
        cats = self._category_breakdown()
        duration = str(self.end_time - self.start_time).split(".")[0]

        summary_cards = "".join(
            f'<div class="card"><div class="card-num">{counts.get(s.value, 0)}</div>'
            f'<div class="card-label">{s.value}</div></div>'
            for s in ToolStatus
        )

        cat_rows = "".join(
            f"<tr><td>{html.escape(cat)}</td><td>{v['total']}</td>"
            f"<td class='ok'>{v['success']}</td><td class='bad'>{v['failed']}</td>"
            f"<td class='muted'>{v['other']}</td></tr>"
            for cat, v in sorted(cats.items())
        )

        parts = []
        for r in self.results:
            badge_class = r.status.name.lower()
            output_html = html.escape(r.output or "(no output)")
            parts.append(f"""
            <div class="result-item">
              <div class="result-head">
                <span class="badge {badge_class}">{html.escape(r.status.value)}</span>
                <span class="rt-name">{html.escape(r.tool)}</span>
                <span class="rt-cat">{html.escape(r.category)}</span>
                <span class="rt-time">{html.escape(r.started_at)} &middot; {r.duration_s:.2f}s</span>
              </div>
              <div class="rt-cmd"><code>{html.escape(r.command)}</code></div>
              <details class="rt-output"><summary>Output</summary><pre>{output_html}</pre></details>
            </div>""")
        result_rows_html = "".join(parts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CSF-WARP Security Assessment Report</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<header class="hero">
  <div class="hero-inner">
    <div class="brand">CSF<span>-WARP</span></div>
    <div class="brand-sub">Cyber Squad Forge &mdash; Weaponized Assessment &amp; Recon Platform</div>
  </div>
</header>
<main>
  <section class="meta-grid">
    <div class="meta-box"><span>Operator</span><strong>{html.escape(self.operator)}</strong></div>
    <div class="meta-box"><span>Scope</span><strong>{html.escape(self.scope)}</strong></div>
    <div class="meta-box"><span>Start</span><strong>{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</strong></div>
    <div class="meta-box"><span>End</span><strong>{self.end_time.strftime('%Y-%m-%d %H:%M:%S')}</strong></div>
    <div class="meta-box"><span>Duration</span><strong>{duration}</strong></div>
    <div class="meta-box"><span>Tools Run</span><strong>{len(self.results)}</strong></div>
  </section>

  <h2 class="section-title">Executive Summary</h2>
  <div class="cards">{summary_cards}</div>

  <h2 class="section-title">Category Breakdown</h2>
  <table class="cat-table">
    <thead><tr><th>Category</th><th>Total</th><th>Success</th><th>Failed</th><th>Other</th></tr></thead>
    <tbody>{cat_rows}</tbody>
  </table>

  <h2 class="section-title">Detailed Results</h2>
  <div class="results">{result_rows_html}</div>

  <footer>
    Generated by CSF-WARP v{VERSION} &mdash; {AUTHOR}. For authorized security engagements only.
    This report may contain sensitive information; handle and store it per your engagement's
    data-handling agreement.
  </footer>
</main>
</body>
</html>"""

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.build_html(), encoding="utf-8")
        return path

    def write_json(self, path: Path) -> Path:
        data = {
            "operator": self.operator,
            "scope": self.scope,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "results": [
                {
                    "tool": r.tool, "category": r.category, "command": r.command,
                    "status": r.status.value, "started_at": r.started_at,
                    "duration_s": r.duration_s, "output": r.output, "target": r.target,
                } for r in self.results
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# Interactive application
# ---------------------------------------------------------------------------
class CSFWarpApp:
    def __init__(self):
        self.results: List[ToolResult] = []
        self.scope: str = ""
        self.operator: str = os.environ.get("USER", "operator")
        self.authorized: bool = False
        self.session_dir = SESSIONS_DIR / RUN_ID
        self.raw_dir = self.session_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.runner = ToolRunner(self.raw_dir)
        self.start_time = datetime.now()

    # -- UI --------------------------------------------------------------
    def show_banner(self):
        console.clear()
        art = "\n".join(build_ascii_banner("CSF-WARP"))
        console.print(Align.center(Text(art, style="bold cyan")))
        subtitle = Text()
        subtitle.append("Weaponized Assessment & Recon Platform\n", style="bold magenta")
        subtitle.append(f'v{VERSION} "{CODENAME}"  |  {AUTHOR}\n', style="dim")
        subtitle.append("For authorized security testing and education only.", style="italic red")
        console.print(Align.center(subtitle))
        console.print()

    def authorize_gate(self):
        console.print(Panel(
            "CSF-WARP orchestrates real offensive security tools. Only run it against systems, "
            "networks and applications you own or are explicitly authorized in writing to test. "
            "Unauthorized use may be illegal in your jurisdiction.",
            title="[bold red]Authorization Required[/]", border_style="red"))
        if not Confirm.ask(
            "[bold]I confirm I have written authorization to test the intended target(s)[/]",
            default=False,
        ):
            console.print("[red]Authorization not confirmed. Exiting.[/]")
            sys.exit(1)
        self.authorized = True
        self.scope = Prompt.ask(
            "Define the engagement scope (target IP/CIDR/domain -- optional)", default=""
        )
        logger.info(f"Session authorized. Operator={self.operator} Scope={self.scope or 'unspecified'}")

    def main_menu(self):
        while True:
            table = Table(title="CSF-WARP Main Menu", box=box.ROUNDED, border_style="cyan")
            table.add_column("#", style="bold cyan", width=4)
            table.add_column("Category", style="bold white")
            table.add_column("Tools", style="dim", justify="right")
            for i, cat in enumerate(CATEGORIES, start=1):
                table.add_row(str(i), cat, str(len(TOOL_CATALOG[cat])))
            console.print(table)
            console.print(
                "[bold]\\[R][/] Generate Report   [bold]\\[H][/] Session History   "
                "[bold]\\[T][/] Set Scope   [bold]\\[Q][/] Quit"
            )
            choice = Prompt.ask("Select a category or option").strip().lower()

            if choice in ("q", "quit", "exit"):
                self.quit_flow()
                return
            if choice == "r":
                self.generate_report_flow()
                continue
            if choice == "h":
                self.show_history()
                continue
            if choice == "t":
                self.scope = Prompt.ask("New engagement scope", default=self.scope)
                continue
            if choice.isdigit() and 1 <= int(choice) <= len(CATEGORIES):
                self.category_menu(CATEGORIES[int(choice) - 1])
                continue
            console.print("[red]Invalid selection.[/]")

    def category_menu(self, category: str):
        tools = TOOL_CATALOG[category]
        while True:
            table = Table(title=category, box=box.SIMPLE_HEAVY, border_style="magenta")
            table.add_column("#", width=4, style="bold cyan")
            table.add_column("Tool", style="bold white")
            table.add_column("Mode", style="yellow")
            table.add_column("Installed", style="green")
            table.add_column("Description", style="dim", max_width=50)
            for i, tool in enumerate(tools, start=1):
                if tool.mode in (LaunchMode.REFERENCE, LaunchMode.LIBRARY):
                    installed = "n/a"
                else:
                    installed = "[green]yes[/]" if shutil.which(tool.binary) else "[red]no[/]"
                risk = " [red](HIGH RISK)[/]" if tool.high_risk else ""
                table.add_row(str(i), tool.name + risk, tool.mode.value, installed, tool.description)
            console.print(table)
            choice = Prompt.ask("Select a tool number, or [B]ack").strip().lower()
            if choice in ("b", "back"):
                return
            if choice.isdigit() and 1 <= int(choice) <= len(tools):
                self.run_tool(tools[int(choice) - 1])
                continue
            console.print("[red]Invalid selection.[/]")

    def run_tool(self, tool: ToolDefinition):
        console.print(Panel(
            f"[bold]{tool.name}[/]\n{tool.description}\n[dim]Binary: {tool.binary}[/]",
            border_style="cyan"))
        if tool.notes:
            console.print(f"[yellow]Note:[/] {tool.notes}")

        if tool.high_risk:
            console.print(
                "[bold red]This tool is flagged HIGH RISK "
                "(can disrupt targets, access systems, or deliver payloads).[/]"
            )
            confirm_text = Prompt.ask("Type AUTHORIZED to proceed, or anything else to cancel",
                                       default="")
            if confirm_text.strip().upper() != "AUTHORIZED":
                console.print("[yellow]Cancelled.[/]")
                self.results.append(ToolResult(
                    tool.name, tool.category, "-", ToolStatus.SKIPPED,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0.0,
                    "Skipped by operator at the high-risk confirmation gate.", ""))
                return

        target = ""
        if tool.needs_target and tool.mode not in (LaunchMode.REFERENCE, LaunchMode.LIBRARY):
            target = Prompt.ask("Target (host / URL / domain / file path)",
                                 default=self.scope).strip()
            if not target:
                console.print("[yellow]No target given -- cancelled.[/]")
                return

        extra = ""
        if tool.mode not in (LaunchMode.REFERENCE, LaunchMode.LIBRARY):
            extra = Prompt.ask("Extra arguments (optional)", default=tool.default_args)

        timeout = 300
        if tool.mode == LaunchMode.CLI:
            timeout_str = Prompt.ask("Timeout in seconds", default="300")
            try:
                timeout = int(timeout_str)
            except ValueError:
                timeout = 300

        result = self.runner.run(tool, target, extra, timeout)
        self.results.append(result)
        self._print_result(result)

    def _print_result(self, result: ToolResult):
        color = STATUS_COLORS.get(result.status, "white")
        excerpt = textwrap.shorten(
            result.output or "(no output)", width=600,
            placeholder=" ... [truncated -- see session raw log]"
        )
        console.print(Panel(
            f"[bold]{result.tool}[/]  --  [{color}]{result.status.value}[/{color}]\n"
            f"[dim]Command:[/] {result.command}\n"
            f"[dim]Duration:[/] {result.duration_s:.2f}s\n\n"
            f"{excerpt}",
            border_style=color, title="Result"))

    def show_history(self):
        if not self.results:
            console.print("[yellow]No tools have been run yet this session.[/]")
            return
        table = Table(title="Session History", box=box.SIMPLE, border_style="cyan")
        table.add_column("Time")
        table.add_column("Category")
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Duration (s)")
        for r in self.results:
            color = STATUS_COLORS.get(r.status, "white")
            table.add_row(r.started_at, r.category, r.tool,
                          f"[{color}]{r.status.value}[/{color}]", f"{r.duration_s:.2f}")
        console.print(table)

    def generate_report_flow(self):
        if not self.results:
            console.print("[yellow]No results to report yet.[/]")
            return
        gen = ReportGenerator(self.operator, self.scope, self.start_time, self.results)
        report_path = gen.write(self.session_dir / "report.html")
        json_path = gen.write_json(self.session_dir / "session.json")
        console.print(f"[green]Report saved to:[/] {report_path}")
        console.print(f"[green]Raw session data saved to:[/] {json_path}")
        if Confirm.ask("Open the report in your browser now?", default=True):
            try:
                webbrowser.open(report_path.as_uri())
            except Exception:
                console.print("[yellow]Couldn't auto-open a browser -- open the file manually.[/]")

    def quit_flow(self):
        if self.results and Confirm.ask("Generate a final report before exiting?", default=True):
            self.generate_report_flow()
        console.print("[bold cyan]Stay sharp. -- Cyber Squad Forge[/]")

    def run(self):
        self.show_banner()
        self.authorize_gate()
        try:
            self.main_menu()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/]")
            self.quit_flow()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def print_catalog():
    table = Table(title="CSF-WARP Tool Catalog", box=box.SIMPLE_HEAVY)
    table.add_column("Category")
    table.add_column("Tool")
    table.add_column("Mode")
    table.add_column("Binary")
    for cat in CATEGORIES:
        for tool in TOOL_CATALOG[cat]:
            table.add_row(cat, tool.name, tool.mode.value, tool.binary)
    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        prog="csf-warp",
        description="CSF-WARP -- Cyber Squad Forge offensive security orchestration platform",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--list", action="store_true", help="list the full tool catalog and exit")
    args = parser.parse_args()

    if args.version:
        console.print(f'CSF-WARP v{VERSION} "{CODENAME}" -- {AUTHOR}')
        return
    if args.list:
        print_catalog()
        return

    app = CSFWarpApp()
    try:
        app.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()
