# CSF-WARP

**Cyber Squad Forge Weaponized Assessment & Recon Platform**

A menu-driven orchestration console for Kali Linux that catalogs, launches, and reports on offensive security tools across twelve engagement phases.

## Overview

CSF-WARP does **not** reimplement or bundle any offensive capability itself. It is a wrapper: it checks whether the real, upstream tool is installed on your system, builds the command line you asked for, executes it (or hands the terminal to it, or launches it — depending on the tool's nature), captures the outcome, and rolls everything up into a polished HTML report at the end of the engagement.

## Features

- 📋 Menu-driven console interface built with [rich](https://github.com/Textualize/rich)
- 🗂️ Tool catalog organized into 12 engagement phases:
  - Reconnaissance
  - Vulnerability Scanning
  - Network-Based Attacks
  - Password & Brute-Force Attacks
  - Mobile Security
  - Reverse Engineering
  - Exploitation
  - Post-Exploitation
  - Wireless Attacks
  - Social Engineering & Phishing
  - Web App Penetration Testing
  - Reporting & Documentation
- ✅ Detects whether each catalog tool is installed on your machine
- 🔒 Mandatory authorization gate at session start, plus a second explicit confirmation before any tool flagged high-risk can run
- 🧾 Session history and automatic HTML + JSON reporting for every engagement
- 🗃️ Per-session logging to `~/CSF-WARP/logs`

## Requirements

- Python 3.8+
- Kali Linux (or any Linux distro with the relevant security tools installed)
- The [`rich`](https://pypi.org/project/rich/) Python package

## Installation

```bash
git clone https://github.com/Muhammad-Muzammil-Khokhar/CSF-WARP.git
```
```bash
cd csf-warp
```
```bash
pip3 install rich --break-system-packages
```

## Usage

Run the interactive console:

```bash
python3 csf_warp.py
```

Other options:

```bash
python3 csf_warp.py --version   # print version info
```
```bash
python3 csf_warp.py --list      # list the full tool catalog and exit
```

On startup you'll be asked to confirm you hold written authorization for the engagement, and optionally set a scope (target IP/CIDR/domain). From the main menu you can browse each category, run a tool, view session history, generate a report, or set/change scope.

## Reports

At any point (or on quit), CSF-WARP can generate:
- An HTML report (`report.html`) summarizing every tool run, its status, duration, and output
- A raw JSON session export (`session.json`)

Both are saved under `~/CSF-WARP/sessions/`.

## ⚠️ Legal & Ethical Use

This tool is built **exclusively** for authorized penetration testing, red-teaming, and security education.

- Every session requires the operator to confirm they hold **written authorization** before any tool can be executed.
- Every high-risk tool requires a **second, explicit confirmation**.
- Running these tools against systems you do not own or do not have documented permission to test is **illegal in most jurisdictions** and is not condoned by Cyber Squad Forge.

Use responsibly and only within the scope of a signed engagement.

## License

⚖️ MIT

## Author

[Engineer Muhammad Muzammil Khokhar](https://github.com/Muhammad-Muzammil-Khokhar)

