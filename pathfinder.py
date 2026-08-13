import subprocess
import os
import glob
import platform
import html
from datetime import datetime
BOLD = "\033[1m"
RED = "\033[31m"
BRIGHT_RED = "\033[91m"
RESET = "\033[0m"
def clear_terminal():
	if os.name == "nt":
		os.system("cls")
	else:
		os.system("clear")
clear_terminal()
print(BOLD + BRIGHT_RED, end="")
logo = f"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║    ██████╗  █████╗ ████████╗██╗  ██╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗     ║
║    ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗    ║
║    ██████╔╝███████║   ██║   ███████║█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝    ║
║    ██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗    ║
║    ██║     ██║  ██║   ██║   ██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║    ║
║    ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝    ║
║                                                                                      ║
║                  Compromised Host Enumeration & Reporting Tool                       ║
║                               By: Rotem Bacal                                        ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
"""
print(logo)
print("This tool is intended for building an assessment report about a compromised system, "
      "as well as recommendations on the next actions adversaries could take.")
print()
print("Upload the script to your compromised system, make sure it has a Python interpreter. If not, download manually.")
print()
input("[*] Press enter to continue... ")
clear_terminal()

# section 1: getting user input
# allow the user to choose whether the target is windows or linux
def detect_os():
	system = platform.system() # detects the target operating system
	if system == "Windows":
		return "Windows"
	elif system == "Linux":
		return "Linux"
	else:
		return None # if the target operating system isn't either windows or linux, such as macOS

def ask_target_os(): # lets the operator confirm to override the target OS
	guessed = detect_os()
	if guessed:
		answer = input(f"Detected OS: {guessed}. Press enter to confirm, or type L/W to override: ").strip().lower()
		print()
		if answer in ("", guessed[0].lower()): # "" - if the user pressed enter (empty string) - tuple
			return guessed
		elif answer.startswith("l"):
			return "Linux"
		elif answer.startswith("w"):
			return "Windows"
		return guessed # if the user enters invalid input, the program continues with the detected OS
		
	while True:
		choice = input("[-] Could not auto-detect, Is this machine [L]inux or [W]indows? ").strip().lower()
		if choice.startswith("l"):
			return "Linux"
		elif choice.startswith("w"):
			return "Windows"
		print("[-] Please type 'L' for Linux or 'W' for Windows.")
		print()

# Allow the user to choose where to save the report
def ask_output_path():
	default_path = os.path.join(os.getcwd(), "assessment_report.html")
	path = input(f"Where should the report be saved? [{default_path}] : ").strip()
	print()
	if path:
		return path
	else:
		return default_path

# System information
# ---- LINUX -----
def linux_run_command(command): # a function to run system commands to collect information
	try:
		result = subprocess.run(command, capture_output=True, text=True, timeout=10)
		return result.stdout.strip()
	except (subprocess.SubprocessError, FileNotFoundError, OSError):
		return ""
		
def linux_get_basic_info():
	return {
	"hostname": platform.node(),
	"os_name": platform.system(),
	"os_release": platform.release(),
	"kernel": linux_run_command(["uname", "-r"]),
	"architecture": platform.machine(),
	"distro": linux_run_command(["cat", "/etc/os-release"]),
	"uptime": linux_run_command(["uptime", "-p"]),
	"scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	}
	
def linux_get_user_info():
	username = linux_run_command(["whoami"])
	id_output = linux_run_command(["id"])
	is_root = username == "root" or "uid=0(" in id_output
	sudo_rights = linux_run_command(["sudo", "-n", "-l"])
	return {
	"username": username,
	"id_output": id_output,
	"is_root": is_root,
	"sudo_rights": sudo_rights,
	"groups": linux_run_command(["groups"]),
	"home_dir": os.path.expanduser("~")
	}

def linux_get_local_users():
	users = []
	try:
		import pwd
		skip_shells = ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/bin/nologin", "/usr/bin/false") # skips service accounts
		for entry in pwd.getpwall():
			if entry.pw_shell not in skip_shells:
				users.append({"name": entry.pw_name, "uid": entry.pw_uid, "home": entry.pw_dir, "shell": entry.pw_shell})
	except Exception:
		pass
	return users
	
def linux_get_network_info():
	return {
	"interfaces": linux_run_command(["ip", "a"]) or linux_run_command(["ifconfig"]),
	"routes": linux_run_command(["ip", "route"]),
	"listening_ports": linux_run_command(["ss", "-tulpn"]) or linux_run_command(["netstat", "-tulpn"]),
	"DNS": linux_run_command(["cat", "/etc/resolv.conf"])
	}
	
def linux_get_services():
	return {
	"systemd_services": linux_run_command(["systemctl", "list-units", "--type=service", "--state=running"]),
	"processes": linux_run_command(["ps", "aux"])
	}
	
def linux_get_installed_software():
	dpkg = linux_run_command(["dpkg", "-l"])
	rpm = linux_run_command(["rpm", "-qa"])
	if dpkg:
		return dpkg
	elif rpm:
		return rpm
	else:
		return "[-] Could not enumerate installed packages (no dpkg/rpm found.)"
		
def linux_get_scheduled_tasks():
	return {
	"user_crontab": linux_run_command(["crontab", "-l"]),
	"system_cron_dirs": linux_run_command(["ls", "-la", "/etc/cron.d", "/etc/cron.daily/"]),
	"systemd_timers": linux_run_command(["systemctl", "list-timers", "--all"])
	}
	
def linux_find_suid_binaries():
	return linux_run_command(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"])
	
def linux_find_writable_sensitive_files():
	results = []
	for path in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]:
		if os.path.exists(path):
			results.append({"path": path, "writable_by_current_user": os.access(path, os.W_OK)})
	return results
	
def linux_find_sensitive_files():
	home = os.path.expanduser("~")
	patterns = [
	f"{home}/.ssh/id_*", f"{home}/.ssh/*.pem", f"{home}/**/*.pem", f"{home}/**/.env", f"{home}/**/*_history", f"{home}/.aws/credentials", f"{home}/**/config.php", f"{home}/**/*.kdbx"
	]
	found = []
	for pattern in patterns:
		found.extend(glob.glob(pattern, recursive=True))
	seen, unique_found = set(), []
	for f in found:
		if f not in seen:
			seen.add(f)
			unique_found.append(f)
	return unique_found
	
def collect_linux():
	return {
	"target_os": "Linux", # key used later in the script
	"basic_info": linux_get_basic_info(),
	"user_info": linux_get_user_info(),
	"local_users": linux_get_local_users(),
	"network_info": linux_get_network_info(),
	"services": linux_get_services(),
	"installed_software": linux_get_installed_software(),
	"scheduled_tasks": linux_get_scheduled_tasks(),
	"suid_binaries": linux_find_suid_binaries(),
	"writable_sensitive_files": linux_find_writable_sensitive_files(),
	"sensitive_files_found": linux_find_sensitive_files(),
	"ad_info": linux_run_command(["realm", "list"]) or "Not domain-joined or unable to check (realm not available)."
	}

# ---- WINDOWS -----
def windows_run_command(command): # a function to run windows commands
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            shell=True
        )
        return result.stdout.strip() if result.stdout else ""
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return ""

def windows_get_basic_info():
    return {
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "systeminfo": windows_run_command("systeminfo"),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def windows_get_user_info():
    username = windows_run_command("whoami")
    privileges = windows_run_command("whoami /priv")
    groups = windows_run_command("whoami /groups")
    
    admin_line = next(
    (line for line in groups.splitlines() if "BUILTIN\\Administrators" in line),
    ""
    )
    
    is_admin_group_member = "BUILTIN\\Administrators" in groups
    is_elevated = "Enabled" in admin_line and "deny only" not in admin_line.lower()
    
    return {
        "username": username,
        "privileges": privileges,
        "groups": groups,
        "is_admin_group_member": is_admin_group_member,
        "is_elevated": is_elevated
    }

def windows_get_local_users():
    return windows_run_command("net user")

def windows_get_network_info():
    return {
        "ip_config": windows_run_command("ipconfig /all"),
        "routes": windows_run_command("route print"),
        "listening_ports": windows_run_command("netstat -ano")
    }

def windows_get_services():
    return {
        "services": windows_run_command(
            "sc query type=service state=all"
        ),
        "tasklist_with_services": windows_run_command(
            "tasklist /svc"
        )
    }

def windows_get_installed_software():
    wmic_out = windows_run_command(
        "wmic product get name,version"
    )

    if wmic_out:
        return wmic_out
    return windows_run_command(
        'powershell -Command "'
        'Get-ItemProperty '
        '\'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\' '
        '| Select-Object DisplayName, DisplayVersion '
        '| Format-Table -AutoSize"'
    )

def windows_get_scheduled_tasks():
    return windows_run_command(
        "schtasks /query /fo LIST /v"
    )

def windows_check_privesc():
    hklm = windows_run_command(
        "reg query "
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
        "/v AlwaysInstallElevated"
    )
    hkcu = windows_run_command(
        "reg query "
        "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
        "/v AlwaysInstallElevated"
    )
    always_install_elevated = (
        "0x1" in hklm and
        "0x1" in hkcu
    )
    unquoted_paths = windows_run_command(
        'wmic service get name,pathname,startmode '
        '| findstr /i /v "\\"" '
        '| findstr /i "Auto"'
    )
    return {
        "always_install_elevated": always_install_elevated,
        "always_install_elevated_raw": {
            "hklm": hklm,
            "hkcu": hkcu
        },
        "unquoted_service_paths": unquoted_paths
    }

def windows_find_sensitive_files():
    home = os.path.expanduser("~")
    patterns = [
        f"{home}\\.ssh\\id_*",
        f"{home}\\.ssh\\*.pem",
        f"{home}\\**\\*.pem",
        f"{home}\\**\\.env",
        f"{home}\\**\\*_history",
        f"{home}\\.aws\\credentials",
        f"{home}\\**\\config.php",
        f"{home}\\**\\*.kdbx",
        f"{home}\\AppData\\Roaming\\**\\*password*",
        f"{home}\\Desktop\\**\\*.txt"
    ]
    found = []
    for pattern in patterns:
        found.extend(
            glob.glob(pattern, recursive=True)
        )
    seen = set()
    unique_found = []
    for path in found:
        if path not in seen:
            seen.add(path)
            unique_found.append(path)
    return unique_found

def windows_get_ad_info():
    domain_info = windows_run_command(
        "echo %USERDOMAIN%"
    )
    part_of_domain = windows_run_command(
        "wmic computersystem get partofdomain"
    )
    if not part_of_domain:
        part_of_domain = windows_run_command(
        'powershell -Command "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"'
        )
    if "TRUE" in part_of_domain.upper():
        domain_controllers = windows_run_command(
            "nltest /dclist:"
        )
    else:
        domain_controllers = ""
    return {
        "user_domain": domain_info,
        "part_of_domain_raw": part_of_domain,
        "domain_controllers": domain_controllers
    }

def collect_windows():
    sensitive_files = windows_find_sensitive_files()
    return {
        "target_os": "Windows",
        "basic_info": windows_get_basic_info(),
        "user_info": windows_get_user_info(),
        "local_users": windows_get_local_users(),
        "network_info": windows_get_network_info(),
        "services": windows_get_services(),
        "installed_software": windows_get_installed_software(),
        "scheduled_tasks": windows_get_scheduled_tasks(),
        "privesc_checks": windows_check_privesc(),
        "sensitive_files_found": sensitive_files,
        "ad_info": windows_get_ad_info()
    }

# ---- SECURITY ASSESSMENT AND RECOMMENDATIONS -----
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
 
KNOWN_VULNERABLE_VERSIONS = {
    "openssh-server": ("7.7", "CVE-2018-15473 (user enumeration) and earlier OpenSSH issues"),
    "apache2": ("2.4.29", "Multiple CVEs patched in later 2.4.x releases"),
    "mysql-server": ("5.7.33", "Several CVEs patched in later 5.7.x releases"),
    "microsoft sql server 2014": ("12.0.2000.8", "Out of mainstream support; missing years of patches"),
}
 
 
def make_finding(title, severity, category, description, evidence):
    return {
        "title": title, "severity": severity, "category": category,
        "description": description,
        "evidence": evidence if evidence else "No direct evidence captured.",
    }
 
 
def assess_privilege_escalation(data):
    findings = []
    os_type = data["target_os"]
 
    if os_type == "Linux":
        sudo_rights = data["user_info"].get("sudo_rights", "")
        if sudo_rights and "NOPASSWD" in sudo_rights:
            findings.append(make_finding(
                "Passwordless sudo rights on sensitive commands", "Critical", "Privilege Escalation",
                "The current user can run at least one command as root without a password. "
                "Depending on the command, this can often be leveraged to obtain a full root "
                "shell (e.g. via GTFOBins-style techniques).", sudo_rights))
 
        suid = data.get("suid_binaries", "")
        common_suid = {"/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount",
                       "/usr/bin/umount", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd",
                       "/usr/bin/newgrp"}
        unusual_suid = [line for line in suid.splitlines() if line and line not in common_suid]
        if unusual_suid:
            findings.append(make_finding(
                "Non-standard SUID binaries present", "High", "Privilege Escalation",
                "SUID binaries run with the file owner's privileges (often root). Binaries "
                "outside the standard set should be checked against known privilege-escalation "
                "techniques (e.g. GTFOBins).", "\n".join(unusual_suid)))
 
        for item in data.get("writable_sensitive_files", []):
            if item.get("writable_by_current_user"):
                findings.append(make_finding(
                    f"{item['path']} is writable by the current user", "Critical", "Privilege Escalation",
                    f"{item['path']} should never be writable by a non-root user. This alone is "
                    "typically enough to escalate to root.", str(item)))
 
    elif os_type == "Windows":
        privesc = data.get("privesc_checks", {})
        if privesc.get("always_install_elevated"):
            findings.append(make_finding(
                "AlwaysInstallElevated is enabled", "Critical", "Privilege Escalation",
                "Both HKLM and HKCU AlwaysInstallElevated registry values are set to 1. Any "
                "local user can install an .msi package that runs with SYSTEM privileges -- a "
                "fast, reliable path to full admin.", str(privesc.get("always_install_elevated_raw", ""))))
        unquoted = privesc.get("unquoted_service_paths", "")
        if unquoted:
            findings.append(make_finding(
                "Unquoted service path detected", "High", "Privilege Escalation",
                "A service binary path contains a space and is not wrapped in quotes. If an "
                "attacker can write to an earlier segment of that path, Windows may execute a "
                "planted binary instead.", unquoted))
 
    return findings
 
 
def assess_sensitive_data(data):
    findings = []
    sensitive_files = data.get("sensitive_files_found", [])
    if sensitive_files:
        findings.append(make_finding(
            "Potentially sensitive files discovered", "High", "Sensitive Data Exposure",
            "Files matching patterns for SSH keys, credential files, .env files, or password "
            "stores were found readable by the current user. Each should be manually reviewed "
            "to confirm what it contains.", "\n".join(sensitive_files)))
    return findings
 
 
def assess_scheduled_tasks(data):
    findings = []
    os_type = data["target_os"]
 
    if os_type == "Linux":
        cron_dirs = data.get("scheduled_tasks", {}).get("system_cron_dirs", "")
        if "rwxrwxrwx" in cron_dirs:
            findings.append(make_finding(
                "World-writable cron file or directory", "Critical", "Scheduled Tasks",
                "A cron job or its containing directory is writable by any user. Since cron "
                "jobs typically run as root, this allows arbitrary code execution as root on "
                "the next scheduled run.", cron_dirs))
        user_cron = data.get("scheduled_tasks", {}).get("user_crontab", "")
        if user_cron:
            findings.append(make_finding(
                "User-level cron job present", "Info", "Scheduled Tasks",
                "The current user has at least one scheduled cron job. Review it for hardcoded "
                "credentials or scripts writable by other users.", user_cron))
 
    elif os_type == "Windows":
        tasks = data.get("scheduled_tasks", "")
        if "SYSTEM" in tasks:
            findings.append(make_finding(
                "Scheduled task runs as SYSTEM", "Medium", "Scheduled Tasks",
                "At least one scheduled task executes as SYSTEM. If the script or binary it "
                "runs is writable by a lower-privileged user, this is a direct path to "
                "SYSTEM-level code execution.", tasks))
 
    return findings
 
 
def assess_ad(data):
    findings = []
    os_type = data["target_os"]
    ad_info = data.get("ad_info", "")
 
    if os_type == "Windows" and isinstance(ad_info, dict):
        if "TRUE" in ad_info.get("part_of_domain_raw", ""):
            findings.append(make_finding(
                "Machine is domain-joined", "Info", "Active Directory",
                "This host is joined to an Active Directory domain. A compromised domain-joined "
                "host is a foothold that can potentially be used for lateral movement or further "
                "AD enumeration (e.g. BloodHound).", str(ad_info)))
    elif os_type == "Linux" and "Not domain-joined" not in str(ad_info):
        findings.append(make_finding(
            "Linux host joined to a domain (via SSSD/realmd)", "Info", "Active Directory",
            "This Linux machine appears to be integrated with a domain, which may expose domain "
            "credentials or trust relationships.", str(ad_info)))
 
    return findings
 
 
def assess_known_vulnerable_software(data):
    findings = []
    software_blob = str(data.get("installed_software", "")).lower()
    for name, (vulnerable_version, note) in KNOWN_VULNERABLE_VERSIONS.items():
        if name in software_blob and vulnerable_version in software_blob:
            findings.append(make_finding(
                f"Potentially outdated: {name} {vulnerable_version}", "High", "Known Vulnerabilities",
                f"This version was detected in the installed software list. {note}. Confirm the "
                "exact patch level and check it against current CVE databases before relying on "
                "this flag alone.", data.get("installed_software", "")))
    return findings
 
 
def run_assessment(data):
    findings = []
    findings += assess_privilege_escalation(data)
    findings += assess_sensitive_data(data)
    findings += assess_scheduled_tasks(data)
    findings += assess_ad(data)
    findings += assess_known_vulnerable_software(data)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return findings
 
 
def build_recommendations(findings):
    action_map = {
        "Privilege Escalation": "Attempt to escalate privileges using this specific weakness "
                                 "before doing anything else on the host.",
        "Sensitive Data Exposure": "Manually inspect the files listed as evidence for live "
                                    "credentials, keys, or tokens that can be reused elsewhere "
                                    "(credential reuse / lateral movement).",
        "Scheduled Tasks": "Check whether the script or binary this task/job runs is writable "
                            "by the current user; if so, plant a payload for the next scheduled run.",
        "Active Directory": "Use these domain details to plan further enumeration (e.g. "
                             "BloodHound, LDAP queries) rather than acting immediately.",
        "Known Vulnerabilities": "Research public exploits for this exact version before "
                                  "attempting anything destructive or noisy.",
    }
 
    recommendations = []
    for finding in findings:
        recommendations.append({
            "priority_rank": None,
            "severity": finding["severity"],
            "action": action_map.get(finding["category"], "Review this finding manually."),
            "reason": finding["description"],
            "linked_finding": finding["title"],
            "evidence": finding["evidence"],
        })
 
    recommendations.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 99))
    for i, rec in enumerate(recommendations, start=1):
        rec["priority_rank"] = i
    return recommendations
 
 
def calculate_risk_score(findings):
    weights = {"Critical": 25, "High": 15, "Medium": 7, "Low": 3, "Info": 0}
    score = min(sum(weights.get(f["severity"], 0) for f in findings), 100)
 
    if score >= 70:
        rating = "Critical Risk"
    elif score >= 40:
        rating = "High Risk"
    elif score >= 15:
        rating = "Moderate Risk"
    else:
        rating = "Low Risk"
 
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
 
    return {"score": score, "rating": rating, "counts": counts}
    
CSS_STYLES = """
:root {
    --bg: #0a0e17; --panel: #111827; --panel-alt: #0d1420; --border: #1e293b;
    --accent: #22d3ee; --text: #e2e8f0; --text-muted: #7d8b9e;
    --critical: #f0466a; --high: #f5a623; --medium: #eab308; --low: #34d399; --info: #60a5fa;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, sans-serif; line-height: 1.6; }
h1, h2, h3, h4, .badge, .evidence, .stat-value { font-family: 'JetBrains Mono', 'Fira Code', monospace; }
.top-banner { background: linear-gradient(120deg, #0d1420 0%, #0a0e17 100%); border-bottom: 1px solid var(--border); padding: 28px 40px; }
.top-banner .eyebrow { color: var(--accent); letter-spacing: 3px; font-size: 12px; text-transform: uppercase; margin: 0 0 8px 0; }
.top-banner h1 { margin: 0; font-size: 26px; letter-spacing: 1px; }
.top-banner .meta-line { color: var(--text-muted); font-size: 13px; margin-top: 10px; }
.top-banner .meta-line span { color: var(--text); }
.layout { display: flex; align-items: flex-start; gap: 24px; padding: 24px 40px 60px 40px; }
.sidebar { width: 300px; flex-shrink: 0; position: sticky; top: 24px; display: flex; flex-direction: column; gap: 16px; }
.main-content { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 28px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
.panel h3 { margin: 0 0 14px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--accent); }
.kv-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.kv-row:last-child { border-bottom: none; }
.kv-row .k { color: var(--text-muted); }
.kv-row .v { color: var(--text); text-align: right; word-break: break-word; }
.risk-meter-wrap { display: flex; flex-direction: column; align-items: center; gap: 10px; }
.risk-meter { width: 130px; height: 130px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
.risk-meter .inner { width: 100px; height: 100px; border-radius: 50%; background: var(--panel); display: flex; flex-direction: column; align-items: center; justify-content: center; }
.risk-meter .score { font-size: 26px; font-weight: 700; }
.risk-meter .score-label { font-size: 9px; color: var(--text-muted); letter-spacing: 1px; }
.risk-rating { font-size: 13px; letter-spacing: 1px; text-transform: uppercase; }
.stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.stat-box { background: var(--panel-alt); border: 1px solid var(--border); border-radius: 8px; padding: 10px; text-align: center; }
.stat-value { font-size: 20px; font-weight: 700; }
.stat-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }
.section-title { display: flex; align-items: center; gap: 10px; font-size: 18px; margin: 0 0 4px 0; }
.section-title .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); display: inline-block; }
.section-sub { color: var(--text-muted); font-size: 13px; margin: 0 0 16px 0; }
.card { background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 8px; padding: 18px 20px; margin-bottom: 14px; }
.card.sev-critical { border-left-color: var(--critical); }
.card.sev-high { border-left-color: var(--high); }
.card.sev-medium { border-left-color: var(--medium); }
.card.sev-low { border-left-color: var(--low); }
.card.sev-info { border-left-color: var(--info); }
.card-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 8px; }
.card-header h4 { margin: 0; font-size: 15px; }
.badge { font-size: 10px; padding: 3px 9px; border-radius: 20px; text-transform: uppercase; letter-spacing: 1px; white-space: nowrap; }
.badge.sev-critical { background: rgba(240,70,106,0.15); color: var(--critical); }
.badge.sev-high { background: rgba(245,166,35,0.15); color: var(--high); }
.badge.sev-medium { background: rgba(234,179,8,0.15); color: var(--medium); }
.badge.sev-low { background: rgba(52,211,153,0.15); color: var(--low); }
.badge.sev-info { background: rgba(96,165,250,0.15); color: var(--info); }
.card .category-tag { color: var(--text-muted); font-size: 11px; margin-bottom: 10px; display: block; }
.card p { margin: 0 0 12px 0; font-size: 13.5px; color: var(--text); }
.evidence { background: var(--panel-alt); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; font-size: 12px; color: #a7f3d0; white-space: pre-wrap; word-break: break-word; max-height: 220px; overflow-y: auto; }
.evidence-label { font-size: 10px; color: var(--accent); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; display: block; }
.priority-num { width: 26px; height: 26px; border-radius: 6px; background: rgba(34,211,238,0.12); color: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; flex-shrink: 0; }
.rec-header { display: flex; gap: 12px; align-items: center; margin-bottom: 8px; }
.empty-state { color: var(--text-muted); font-size: 13px; font-style: italic; padding: 12px 0; }
footer.report-footer { text-align: center; color: var(--text-muted); font-size: 11px; padding: 30px 40px 40px 40px; border-top: 1px solid var(--border); margin-top: 20px; }
@media (max-width: 900px) { .layout { flex-direction: column; } .sidebar { width: 100%; position: static; } }
"""
 
def esc(value):
    return html.escape(str(value)) if value else ""
 
def render_kv_rows(pairs):
    rows = ""
    for label, value in pairs:
        rows += f'<div class="kv-row"><span class="k">{esc(label)}</span><span class="v">{esc(value)}</span></div>\n'
    return rows
 
def render_system_summary_panel(data):
    basic = data.get("basic_info", {})
    user = data.get("user_info", {})
    os_type = data["target_os"]
 
    if os_type == "Linux":
        pairs = [
            ("Hostname", basic.get("hostname")),
            ("OS", f"{basic.get('os_name')} {basic.get('os_release')}"),
            ("Architecture", basic.get("architecture")),
            ("Kernel", basic.get("kernel")),
            ("Uptime", basic.get("uptime")),
            ("Current user", user.get("username")),
            ("Privilege level", "root" if user.get("is_root") else "non-root"),
            ("Scan time", basic.get("scan_time")),
        ]
        
    else:
        if user.get("is_elevated"):
            priv_display = "admin (elevated)"
        elif user.get("is_admin_group_member"):
            priv_display = "standard user (admin group - UAC restricted)"
        else:
            priv_display = "standard user"
		
        pairs = [
            ("Hostname", basic.get("hostname")),
            ("OS", basic.get("os_version")),
            ("Architecture", basic.get("architecture")),
            ("Current user", user.get("username")),
            ("Privilege level", priv_display),
            ("Scan time", basic.get("scan_time")),
        ]
 
    return f'<div class="panel"><h3>System Summary</h3>{render_kv_rows(pairs)}</div>'
 
def render_risk_meter_panel(risk):
    score, rating, counts = risk["score"], risk["rating"], risk["counts"]
 
    if score >= 70:
        ring_color = "#f0466a"
    elif score >= 40:
        ring_color = "#f5a623"
    elif score >= 15:
        ring_color = "#eab308"
    else:
        ring_color = "#34d399"
 
    ring_style = f"background: conic-gradient({ring_color} {score * 3.6}deg, #1e293b {score * 3.6}deg);"
 
    stat_boxes = ""
    for sev, color_var in [("Critical", "var(--critical)"), ("High", "var(--high)"),
                            ("Medium", "var(--medium)"), ("Low", "var(--low)")]:
        stat_boxes += (f'<div class="stat-box"><div class="stat-value" style="color:{color_var}">'
                        f'{counts.get(sev, 0)}</div><div class="stat-label">{sev}</div></div>')
    return f"""
    <div class="panel">
        <h3>Risk Score</h3>
        <div class="risk-meter-wrap">
            <div class="risk-meter" style="{ring_style}">
                <div class="inner"><div class="score">{score}</div><div class="score-label">/ 100</div></div>
            </div>
            <div class="risk-rating" style="color:{ring_color}">{esc(rating)}</div>
        </div>
        <div class="stat-grid" style="margin-top:16px;">{stat_boxes}</div>
    </div>
    """
def render_network_info_section(data):
    net = data.get("network_info", {})
    if not net:
        return ""

    if data["target_os"] == "Linux":
        blocks = [
            ("Interfaces", net.get("interfaces")),
            ("Routes", net.get("routes")),
            ("Listening Ports", net.get("listening_ports")),
            ("DNS", net.get("DNS"))
        ]
    else:
        blocks = [
            ("IP Configuration", net.get("ip_config")),
            ("Routes", net.get("routes")),
            ("Listening Ports", net.get("listening_ports"))
        ]

    cards = ""

    for label, content in blocks:
        if content:
            cards += f"""
            <div class="card">
                <div class="card-header"><h4>{esc(label)}</h4></div>
                <div class="evidence">{esc(content)}</div>
            </div>
            """

    return f"""
    <section>
        <h2 class="section-title"><span class="dot"></span>Network Configuration</h2>
        <p class="section-sub">Raw network data collected from the target during enumeration.</p>
        {cards}
    </section>
    """
	
def render_finding_card(finding):
    sev_class = f"sev-{finding['severity'].lower()}"
    return f"""
    <div class="card {sev_class}">
        <div class="card-header">
            <h4>{esc(finding['title'])}</h4>
            <span class="badge {sev_class}">{esc(finding['severity'])}</span>
        </div>
        <span class="category-tag">{esc(finding['category'])}</span>
        <p>{esc(finding['description'])}</p>
        <span class="evidence-label">Evidence</span>
        <div class="evidence">{esc(finding['evidence'])}</div>
    </div>
    """
 
def render_recommendation_card(rec):
    sev_class = f"sev-{rec['severity'].lower()}"
    return f"""
    <div class="card {sev_class}">
        <div class="rec-header">
            <span class="priority-num">{rec['priority_rank']}</span>
            <div>
                <h4 style="margin:0;">{esc(rec['action'])}</h4>
                <span class="category-tag" style="margin:2px 0 0 0;">Linked finding: {esc(rec['linked_finding'])}</span>
            </div>
            <span class="badge {sev_class}" style="margin-left:auto;">{esc(rec['severity'])}</span>
        </div>
        <p><strong>Why:</strong> {esc(rec['reason'])}</p>
        <span class="evidence-label">Supporting Evidence</span>
        <div class="evidence">{esc(rec['evidence'])}</div>
    </div>
    """
 
def generate_html_report(data, findings, recommendations, risk, output_path,
                          student_name="Rotem Bacal", student_code="s17", class_code="RTX 2026", lecturer="David Shiffman"):
    basic = data.get("basic_info", {})
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
 
    findings_html = "".join(render_finding_card(f) for f in findings) if findings else \
        '<div class="empty-state">No notable findings were identified during this assessment.</div>'
    recommendations_html = "".join(render_recommendation_card(r) for r in recommendations) if recommendations else \
        '<div class="empty-state">No recommendations to make -- no actionable findings were identified.</div>'
 
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Assessment Report - {esc(basic.get('hostname', 'target'))}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>{CSS_STYLES}</style>
</head>
<body>
 
<div class="top-banner">
    <p class="eyebrow">Cyber Warfare &middot; Project: Pathfinder &middot; ZX310</p>
    <h1>Post-Compromise Assessment Report</h1>
    <div class="meta-line">
        Target: <span>{esc(basic.get('hostname', 'unknown'))}</span> &nbsp;|&nbsp;
        OS: <span>{esc(data['target_os'])}</span> &nbsp;|&nbsp;
        Generated: <span>{esc(generated_at)}</span>
    </div>
</div>
 
<div class="layout">
    <div class="sidebar">
        {render_system_summary_panel(data)}
        {render_risk_meter_panel(risk)}
        <div class="panel">
            <h3>Project Info</h3>
            {render_kv_rows([
                ("Student", student_name or "-"),
                ("Student code", student_code or "-"),
                ("Class code", class_code or "-"),
                ("Lecturer", lecturer or "-"),
            ])}
        </div>
    </div>
 
    <div class="main-content">
        {render_network_info_section(data)}
        <section>
            <h2 class="section-title"><span class="dot"></span>Findings</h2>
            <p class="section-sub">Security-relevant facts discovered during the assessment, ordered by severity.</p>
            {findings_html}
        </section>
 
        <section>
            <h2 class="section-title"><span class="dot"></span>Recommendations</h2>
            <p class="section-sub">Suggested next actions, ordered from highest to lowest priority. Each is tied to the finding that justifies it.</p>
            {recommendations_html}
        </section>
    </div>
</div>
 
<footer class="report-footer">
    Generated automatically by the Pathfinder assessment tool for educational use (ZX310 - Cyber Warfare).
</footer>
 
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return output_path
def main():
	target_os = ask_target_os()
	output_path = ask_output_path()
	print(f"Target OS: {target_os}")
	print("[+] Collecting System information... this may take a moment.")
	data = collect_linux() if target_os == "Linux" else collect_windows()
	print()
	print("[+] Collection complete. Running security assessment...")
	findings = run_assessment(data)
	recommendations = build_recommendations(findings)
	risk = calculate_risk_score(findings)
	print(f"[+] Assessment complete: {len(findings)} finding(s), risk score {risk['score']}/100 ({risk['rating']}).")
	print()
	print("[+] Generating HTML report...")
	generate_html_report(data, findings, recommendations, risk, output_path)
	print()
	print(f"[+] Done. Report saved to: {output_path}")
	
if __name__ == "__main__":
	main()
