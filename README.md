# Pathfinder

**Compromised Host Enumeration & Reporting Tool**

Pathfinder is a Python tool built for the post-exploitation phase of a security engagement. Dropped onto a compromised host, it enumerates the system, runs the collected data through a set of security checks, and outputs a single self-contained HTML report — risk-scored, severity-sorted, and with every recommendation traced back to the evidence that justifies it.

> ⚠️ **For authorized security testing and educational use only.** Only run this tool on systems you own or have explicit written permission to test.

---

## Why

After initial access, an operator has to manually run dozens of commands to understand the target environment — misconfigurations, privilege escalation paths, outdated software, exposed credentials. That process is slow and easy to lose track of. Pathfinder automates the collection and presents it as a clear, prioritized report, so an operator can go from raw enumeration data to a next-action plan without sifting through command output by hand.

## Features

- **OS-aware enumeration** — automatically detects Windows or Linux and runs the appropriate native commands for each (`systeminfo`/`ipconfig`/WMI vs. `uname`/`ip a`/`dpkg`/`rpm`), with graceful fallback if a primary collection method isn't available on the target.
- **Structured security checks**, each producing a finding with severity, category, description, and supporting evidence:
  - **Privilege Escalation** — passwordless sudo, unusual SUID binaries, world-writable sensitive files, AlwaysInstallElevated, unquoted service paths
  - **Sensitive Data** — SSH keys, `.env` files, credential stores, and password vaults found via pattern matching
  - **Scheduled Tasks** — world-writable cron jobs/directories, SYSTEM-level scheduled tasks
  - **Active Directory** — domain-joined status and domain controller enumeration
  - **Known Vulnerable Software** — installed software checked against known-vulnerable versions
- **Risk scoring** — an overall 0–100 score (Critical = 25, High = 15, Medium = 7, Low = 3, Info = 0 per finding, capped at 100) with a Low/Moderate/High/Critical rating.
- **Self-contained HTML report** — a single `assessment_report.html` file, viewable in any browser, with a system summary sidebar, visual risk gauge, and findings/recommendations that link back to the raw evidence.

## Requirements

- Python 3.x installed on the target host (the operator confirms or installs this before running)
- No external dependencies beyond the standard library *(update this if you added any)*

## Usage

1. Copy `pathfinder.py` to the target system.
2. Run it:
   ```bash
   python3 pathfinder.py
   ```
3. Confirm or override the auto-detected OS when prompted.
4. Choose where to save the report (defaults to the current directory).
5. Open `assessment_report.html` in a browser to review findings and recommendations.

## How it works

1. **Delivery & interpreter check** — confirms Python is available on the target.
2. **OS detection** — detects Windows/Linux via `platform.system()`, with manual override.
3. **Enumeration** — collects system info, current user/privilege level, network config, running services, and installed software using OS-native commands.
4. **Assessment** — runs collected data through the security checks above, producing structured findings sorted by severity.
5. **Report generation** — renders findings and recommendations into a single HTML report.

## Disclaimer

This tool is intended for use in authorized penetration testing, red team engagements, and educational lab environments only. Running enumeration tools against systems without explicit authorization is illegal. The author is not responsible for misuse of this tool.

## Author

Built by Rotem Bacal as a Cyber Warfare course project.
