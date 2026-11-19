"""Static threat knowledge base.

Attack-pattern playbooks (how an attack works, how it can be carried out,
MITRE ATT&CK / D3FEND mapping, detections and mitigations), plus keyword
taxonomies for industry and region classification.
"""

# --------------------------------------------------------------------------
# Attack patterns. Each one is a "playbook" used to build threat reports.
#   keywords   - lower-case phrases used to classify news / CVEs
#   chain      - ordered attack stages: (stage, what the attacker does, technique ids)
#   behaviour  - behavioural hunt queries per SIEM (independent of IOCs)
# --------------------------------------------------------------------------
ATTACK_PATTERNS = {
    "ransomware": {
        "name": "Ransomware & Data Extortion",
        "icon": "🔒",
        "color": "#ef4444",
        "keywords": ["ransomware", "ransom", "extortion", "lockbit", "akira", "blackcat", "alphv",
                     "play ransomware", "clop", "cl0p", "black basta", "rhysida", "medusa", "qilin",
                     "encryptor", "double extortion", "leak site", "scattered spider", "8base",
                     "ransomhub", "bianlian", "interlock", "safepay", "dragonforce"],
        "summary": "Operators gain access, escalate privileges, exfiltrate data and then encrypt "
                   "systems, demanding payment for a decryptor and to stop publishing stolen data.",
        "chain": [
            ("Initial Access", "Exploit an internet-facing VPN/firewall/RMM, use stolen credentials, or phishing with a loader (e.g. via an initial access broker).", ["T1190", "T1078", "T1566"]),
            ("Execution", "Run PowerShell / cmd, drop Cobalt Strike, Sliver or similar beacons.", ["T1059.001", "T1059.003"]),
            ("Persistence", "Create services, scheduled tasks or new local/domain accounts; install legit RMM tools (AnyDesk, ScreenConnect).", ["T1543.003", "T1053.005", "T1136", "T1219"]),
            ("Privilege Escalation & Credential Access", "Dump LSASS, Kerberoast, DCSync to obtain domain admin.", ["T1003.001", "T1558.003", "T1003.006"]),
            ("Discovery & Lateral Movement", "AdFind/BloodHound recon, move via RDP, SMB/PsExec, WMI.", ["T1087.002", "T1021.001", "T1021.002", "T1047"]),
            ("Defense Evasion", "Disable EDR (BYOVD), clear logs, tamper with security tools.", ["T1562.001", "T1070.001", "T1068"]),
            ("Exfiltration", "Stage archives and exfiltrate with rclone / MEGA / cloud storage.", ["T1560.001", "T1567.002"]),
            ("Impact", "Delete shadow copies and backups, encrypt files, drop ransom note.", ["T1490", "T1486"]),
        ],
        "detection": [
            "vssadmin / wmic shadowcopy delete, bcdedit recovery disabled",
            "Mass file rename / high-entropy writes in a short window",
            "rclone, MEGAsync or unusual large outbound transfers",
            "New RMM tool installs (AnyDesk, ScreenConnect, Atera) on servers",
            "LSASS access from non-security processes",
        ],
        "mitigations": [
            "Patch internet-facing edge devices first (CISA KEV list)",
            "Enforce phishing-resistant MFA on VPN, RDP and admin accounts",
            "Immutable / offline backups and tested restores",
            "Tiered admin model, LAPS, disable NTLM where possible",
            "EDR tamper protection and vulnerable-driver blocklist",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "PROCESS_LAUNCH" AND (target.process.command_line = /vssadmin.*delete.*shadows/ nocase OR target.process.command_line = /wmic.*shadowcopy.*delete/ nocase OR target.process.command_line = /bcdedit.*recoveryenabled.*no/ nocase OR target.process.command_line = /wbadmin.*delete/ nocase)',
            "splunk": 'index=* (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) OR (sourcetype=WinEventLog:Security EventCode=4688)\n| search CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*"\n| stats count min(_time) as first max(_time) as last by host, user, CommandLine',
            "sentinel": 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("vssadmin", "wmic", "bcdedit", "wbadmin")\n| where ProcessCommandLine matches regex @"(?i)(delete\\s+shadows|shadowcopy\\s+delete|recoveryenabled\\s+no|wbadmin.*delete)"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName',
            "elastic": 'process.command_line : (*vssadmin*delete*shadows* or *shadowcopy*delete* or *recoveryenabled*no* or *wbadmin*delete*)',
            "qradar": "SELECT DATEFORMAT(starttime,'yyyy-MM-dd HH:mm') AS t, sourceip, username, \"Process CommandLine\" FROM events WHERE (\"Process CommandLine\" ILIKE '%vssadmin%delete%shadows%' OR \"Process CommandLine\" ILIKE '%shadowcopy%delete%' OR \"Process CommandLine\" ILIKE '%recoveryenabled%no%') LAST 7 DAYS",
        },
    },
    "phishing": {
        "name": "Phishing & Social Engineering",
        "icon": "🎣",
        "color": "#f59e0b",
        "keywords": ["phishing", "phish", "spear-phishing", "smishing", "vishing", "credential harvesting",
                     "lure", "malicious attachment", "adversary-in-the-middle", "aitm", "evilginx",
                     "qr code", "quishing", "clickfix", "fake captcha", "social engineering", "callback phishing",
                     "teams phishing", "oauth consent"],
        "summary": "Attackers impersonate trusted brands or colleagues to trick users into opening "
                   "malware, entering credentials on fake login pages, or approving MFA prompts.",
        "chain": [
            ("Reconnaissance", "Harvest employee names, emails and roles from LinkedIn and breach data.", ["T1589.002", "T1591.004"]),
            ("Resource Development", "Register look-alike domains, set up AiTM phishing kits (Evilginx, Tycoon 2FA).", ["T1583.001", "T1608.005"]),
            ("Initial Access", "Send emails with links, HTML/SVG/QR attachments, or Teams messages.", ["T1566.001", "T1566.002", "T1566.003"]),
            ("Execution", "User opens attachment or runs a 'ClickFix' copy-paste PowerShell command.", ["T1204.001", "T1204.002", "T1059.001"]),
            ("Credential Access", "Steal passwords and session cookies, bypassing MFA.", ["T1557", "T1539", "T1111"]),
            ("Persistence", "Register attacker MFA device, create inbox rules, OAuth app consent.", ["T1098.005", "T1564.008", "T1550.001"]),
            ("Impact / Follow-on", "BEC fraud, internal phishing, or hand-off to ransomware affiliates.", ["T1534", "T1657"]),
        ],
        "detection": [
            "Sign-ins from new ASN/country immediately after a URL click",
            "New inbox rules that move/delete mail (e.g. 'invoice', 'payment')",
            "explorer.exe / mshta / powershell spawned from browser or Run dialog (ClickFix)",
            "Newly registered domains in email links and DNS",
        ],
        "mitigations": [
            "Phishing-resistant MFA (FIDO2 / passkeys); token protection",
            "Block newly registered domains and HTML/SVG attachments at the gateway",
            "Disable user OAuth consent; admin-approval workflow",
            "User awareness with reporting button; DMARC p=reject",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = /explorer\\.exe$/ nocase AND target.process.file.full_path = /(powershell|mshta|cmd)\\.exe$/ nocase AND target.process.command_line = /(iwr|invoke-webrequest|curl|mshta\\s+http|frombase64string)/ nocase',
            "splunk": 'index=* EventCode=1 ParentImage="*\\\\explorer.exe" (Image="*\\\\powershell.exe" OR Image="*\\\\mshta.exe" OR Image="*\\\\cmd.exe")\n| regex CommandLine="(?i)(iwr|invoke-webrequest|curl|mshta\\s+http|frombase64string)"\n| table _time host user ParentImage Image CommandLine',
            "sentinel": 'DeviceProcessEvents\n| where InitiatingProcessFileName =~ "explorer.exe"\n| where FileName in~ ("powershell.exe","mshta.exe","cmd.exe")\n| where ProcessCommandLine matches regex @"(?i)(iwr|invoke-webrequest|curl|mshta\\s+http|frombase64string)"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
            "elastic": 'process.parent.name : "explorer.exe" and process.name : ("powershell.exe" or "mshta.exe" or "cmd.exe") and process.command_line : (*iwr* or *Invoke-WebRequest* or *FromBase64String* or *mshta*http*)',
            "qradar": "SELECT sourceip, username, \"Process CommandLine\" FROM events WHERE \"Parent Process Name\" ILIKE '%explorer.exe' AND \"Process Name\" IN ('powershell.exe','mshta.exe','cmd.exe') AND (\"Process CommandLine\" ILIKE '%iwr%' OR \"Process CommandLine\" ILIKE '%frombase64string%') LAST 7 DAYS",
        },
    },
    "edge_exploitation": {
        "name": "Edge Device & Public App Exploitation",
        "icon": "🛡️",
        "color": "#8b5cf6",
        "keywords": ["vpn", "firewall", "fortinet", "fortigate", "fortios", "ivanti", "pulse secure", "citrix",
                     "netscaler", "palo alto", "pan-os", "globalprotect", "sonicwall", "cisco asa", "f5 big-ip",
                     "juniper", "check point", "sophos firewall", "zyxel", "edge device", "remote code execution",
                     "rce", "pre-auth", "unauthenticated", "zero-day", "0-day", "actively exploited",
                     "exploited in the wild", "web shell", "webshell", "moveit", "confluence", "exchange server",
                     "sharepoint", "gateway", "appliance"],
        "summary": "Unpatched or zero-day flaws in internet-facing devices and web apps (VPNs, firewalls, "
                   "file-transfer, collaboration servers) are exploited for direct, unauthenticated access.",
        "chain": [
            ("Reconnaissance", "Mass-scan the internet (Shodan/Censys-style) for vulnerable versions.", ["T1595.002", "T1592.002"]),
            ("Initial Access", "Send crafted HTTP requests exploiting auth bypass / RCE / path traversal.", ["T1190"]),
            ("Execution & Persistence", "Drop a web shell or implant on the appliance; modify startup scripts.", ["T1505.003", "T1059.004"]),
            ("Credential Access", "Dump config files, session tokens, LDAP bind credentials from the device.", ["T1552.001", "T1555"]),
            ("Lateral Movement", "Use harvested creds/VPN access to pivot into the internal network.", ["T1078", "T1021"]),
            ("Defense Evasion", "Tamper with device logs and integrity checker; blend in via device IP.", ["T1070", "T1562"]),
        ],
        "detection": [
            "Unusual child processes from web server / appliance services (w3wp, httpd, java)",
            "New files in web roots (.jsp, .aspx, .php) shortly after unusual POSTs",
            "VPN logins for valid accounts from hosting providers / rare geos",
            "Outbound connections initiated *from* the appliance management IP",
        ],
        "mitigations": [
            "Patch KEV-listed edge CVEs within days; apply vendor mitigations immediately",
            "Remove management interfaces from the internet",
            "Run vendor integrity checkers; rotate secrets after compromise",
            "Forward appliance logs to the SIEM; alert on config changes",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = /(w3wp|httpd|nginx|tomcat|java|php-cgi|httpd\\.exe)/ nocase AND target.process.file.full_path = /(cmd\\.exe|powershell\\.exe|\\/bin\\/sh|\\/bin\\/bash|whoami)/ nocase',
            "splunk": 'index=* EventCode=1 (ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\httpd.exe" OR ParentImage="*\\\\tomcat*.exe" OR ParentImage="*\\\\java.exe")\n(Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\whoami.exe")\n| stats count by host ParentImage Image CommandLine',
            "sentinel": 'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","tomcat9.exe","java.exe","php-cgi.exe","nginx.exe")\n| where FileName in~ ("cmd.exe","powershell.exe","whoami.exe","certutil.exe")\n| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine',
            "elastic": 'process.parent.name : ("w3wp.exe" or "httpd" or "java" or "tomcat*" or "nginx") and process.name : ("cmd.exe" or "powershell.exe" or "sh" or "bash" or "whoami*")',
            "qradar": "SELECT sourceip, \"Parent Process Name\", \"Process Name\", \"Process CommandLine\" FROM events WHERE \"Parent Process Name\" IN ('w3wp.exe','httpd.exe','java.exe') AND \"Process Name\" IN ('cmd.exe','powershell.exe','whoami.exe') LAST 7 DAYS",
        },
    },
    "supply_chain": {
        "name": "Software Supply Chain",
        "icon": "📦",
        "color": "#06b6d4",
        "keywords": ["supply chain", "supply-chain", "npm", "pypi", "malicious package", "typosquat",
                     "dependency confusion", "github action", "compromised update", "trojanized",
                     "open source package", "backdoored", "maven", "rubygems", "vs code extension",
                     "browser extension", "build pipeline", "ci/cd", "shai-hulud", "worm"],
        "summary": "Attackers poison trusted software — open-source packages, build pipelines, updates or "
                   "extensions — so victims install the malicious code themselves.",
        "chain": [
            ("Resource Development", "Publish typosquatted packages or hijack maintainer accounts/tokens.", ["T1195.001", "T1586"]),
            ("Initial Access", "Victims install the package / update; CI pipelines pull it automatically.", ["T1195.002"]),
            ("Execution", "Install-time scripts (postinstall, setup.py) run payloads.", ["T1059.007", "T1059.006"]),
            ("Credential Access", "Steal cloud keys, npm/GitHub tokens, SSH keys and env secrets.", ["T1552.001", "T1552.004"]),
            ("Exfiltration & Propagation", "Send secrets to webhooks/GitHub repos; self-propagate to other packages.", ["T1567", "T1041"]),
        ],
        "detection": [
            "node/python spawning curl/wget/bash during package install",
            "New outbound connections from build agents to webhook/paste sites",
            "Use of CI tokens from unexpected IPs",
        ],
        "mitigations": [
            "Pin dependencies with lockfiles + integrity hashes; use internal mirrors",
            "Disable install scripts in CI where possible (npm --ignore-scripts)",
            "Short-lived, least-privilege CI tokens; secret scanning",
            "SBOMs and continuous SCA scanning",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = /(node|npm|python3?|pip)(\\.exe)?$/ nocase AND target.process.command_line = /(curl|wget|Invoke-WebRequest|base64\\s+-d|webhook\\.site|pastebin)/ nocase',
            "splunk": 'index=* EventCode=1 (ParentImage="*node*" OR ParentImage="*python*" OR ParentImage="*npm*")\n| regex CommandLine="(?i)(curl|wget|invoke-webrequest|base64\\s+-d|webhook\\.site|pastebin)"\n| table _time host user ParentImage CommandLine',
            "sentinel": 'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","python.exe","pip.exe","node","python3")\n| where ProcessCommandLine matches regex @"(?i)(curl|wget|invoke-webrequest|base64\\s+-d|webhook\\.site|pastebin)"',
            "elastic": 'process.parent.name : ("node" or "node.exe" or "python*" or "npm*" or "pip*") and process.command_line : (*curl* or *wget* or *webhook.site* or *pastebin*)',
            "qradar": "SELECT sourceip, \"Parent Process Name\", \"Process CommandLine\" FROM events WHERE (\"Parent Process Name\" ILIKE '%node%' OR \"Parent Process Name\" ILIKE '%python%') AND (\"Process CommandLine\" ILIKE '%curl%' OR \"Process CommandLine\" ILIKE '%wget%') LAST 7 DAYS",
        },
    },
    "infostealer": {
        "name": "Infostealers & Credential Theft",
        "icon": "🕵️",
        "color": "#ec4899",
        "keywords": ["infostealer", "info-stealer", "stealer", "lumma", "redline", "vidar", "raccoon",
                     "stealc", "atomic stealer", "amos", "rhadamanthys", "credential theft", "session cookie",
                     "cookie theft", "password stealer", "keylogger", "banking trojan", "malvertising",
                     "fake installer", "cracked software"],
        "summary": "Commodity malware harvests browser passwords, cookies, crypto wallets and tokens, "
                   "which are sold on markets and used for account takeover and intrusions.",
        "chain": [
            ("Initial Access", "Malvertising, SEO poisoning, fake updates, cracked software, ClickFix lures.", ["T1189", "T1204.002", "T1608.006"]),
            ("Execution", "Loader decrypts and injects stealer into a legitimate process.", ["T1055", "T1027"]),
            ("Credential Access", "Read browser credential stores and cookies, wallet files, Telegram/Discord tokens.", ["T1555.003", "T1539", "T1552.001"]),
            ("Collection", "Screenshot, system info, files matching patterns.", ["T1113", "T1005", "T1082"]),
            ("Exfiltration", "POST data to C2 / Telegram bots; logs sold on markets.", ["T1041", "T1567"]),
        ],
        "detection": [
            "Non-browser processes reading Login Data / Cookies / key4.db",
            "Execution from %AppData%/%Temp% of unsigned binaries after downloads",
            "Connections to Telegram API or freshly registered domains from workstations",
        ],
        "mitigations": [
            "Block unsigned software installs; app allow-listing",
            "Browser-based password managers off for corporate SSO; use enterprise PAM",
            "Revoke sessions and rotate creds on any stealer infection",
            "Monitor leaked credential markets for corporate domains",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "FILE_OPEN" AND target.file.full_path = /(Login Data|Cookies|key4\\.db|logins\\.json|Local State)$/ nocase AND NOT principal.process.file.full_path = /(chrome|msedge|firefox|brave|opera)\\.exe$/ nocase',
            "splunk": 'index=* (EventCode=4663 OR EventCode=11) (ObjectName="*\\\\Login Data" OR ObjectName="*\\\\Cookies" OR ObjectName="*key4.db" OR TargetFilename="*\\\\Login Data")\nNOT (ProcessName="*chrome.exe" OR ProcessName="*msedge.exe" OR ProcessName="*firefox.exe")\n| stats count by host ProcessName ObjectName',
            "sentinel": 'DeviceFileEvents\n| where FileName in~ ("Login Data","Cookies","key4.db","logins.json","Local State")\n| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath',
            "elastic": 'file.name : ("Login Data" or "Cookies" or "key4.db" or "logins.json") and not process.name : ("chrome.exe" or "msedge.exe" or "firefox.exe" or "brave.exe")',
            "qradar": "SELECT sourceip, \"Process Name\", \"Filename\" FROM events WHERE \"Filename\" IN ('Login Data','Cookies','key4.db','logins.json') AND \"Process Name\" NOT IN ('chrome.exe','msedge.exe','firefox.exe') LAST 7 DAYS",
        },
    },
    "apt_espionage": {
        "name": "APT / Nation-State Espionage",
        "icon": "🎯",
        "color": "#3b82f6",
        "keywords": ["apt", "nation-state", "state-sponsored", "espionage", "cyber espionage", "lazarus",
                     "apt28", "apt29", "fancy bear", "cozy bear", "volt typhoon", "salt typhoon", "typhoon",
                     "kimsuky", "sandworm", "mustang panda", "muddywater", "charming kitten", "turla",
                     "unc", "threat actor", "chinese hackers", "russian hackers", "north korean", "iranian hackers",
                     "midnight blizzard", "storm-", "blizzard", "sidewinder", "transparent tribe", "apt36"],
        "summary": "Well-resourced state-aligned groups conduct long-term, stealthy intrusions for "
                   "intelligence collection or pre-positioning in critical infrastructure.",
        "chain": [
            ("Reconnaissance", "Target-specific research on personnel, suppliers and exposed assets.", ["T1595", "T1589", "T1593"]),
            ("Initial Access", "Spear-phishing, zero-day edge exploits, trusted-relationship compromise.", ["T1566.001", "T1190", "T1199"]),
            ("Persistence", "Custom implants, firmware/router backdoors, valid accounts.", ["T1505.003", "T1078", "T1542"]),
            ("Defense Evasion", "Living-off-the-land (LOLBins), proxy through compromised SOHO routers.", ["T1218", "T1090.003", "T1027"]),
            ("Credential Access & Discovery", "NTDS.dit extraction, network mapping, email collection.", ["T1003.003", "T1046", "T1114"]),
            ("Collection & Exfiltration", "Collect mail, documents; exfil slowly via encrypted channels.", ["T1114.002", "T1041", "T1048"]),
        ],
        "detection": [
            "ntdsutil / vssadmin create shadow on domain controllers",
            "LOLBin usage (netsh portproxy, wmic, certutil) on servers",
            "Logins from SOHO router / residential proxy IP ranges",
            "Mailbox access via EWS/Graph from unusual apps",
        ],
        "mitigations": [
            "Hunt for living-off-the-land behaviours; baseline admin tooling",
            "Retire end-of-life edge devices and SOHO routers",
            "Long log retention (12+ months) for retroactive hunting",
            "Conditional access and privileged access workstations",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "PROCESS_LAUNCH" AND (target.process.command_line = /ntdsutil.*ifm/ nocase OR target.process.command_line = /netsh.*portproxy/ nocase OR target.process.command_line = /vssadmin.*create\\s+shadow/ nocase OR target.process.command_line = /certutil.*-urlcache/ nocase)',
            "splunk": 'index=* EventCode=1 (CommandLine="*ntdsutil*ifm*" OR CommandLine="*netsh*portproxy*" OR CommandLine="*vssadmin*create shadow*" OR CommandLine="*certutil*-urlcache*")\n| stats count by host user CommandLine',
            "sentinel": 'DeviceProcessEvents\n| where ProcessCommandLine matches regex @"(?i)(ntdsutil.*ifm|netsh.*portproxy|vssadmin.*create\\s+shadow|certutil.*-urlcache)"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine',
            "elastic": 'process.command_line : (*ntdsutil*ifm* or *netsh*portproxy* or *vssadmin*create*shadow* or *certutil*urlcache*)',
            "qradar": "SELECT sourceip, username, \"Process CommandLine\" FROM events WHERE \"Process CommandLine\" ILIKE '%ntdsutil%ifm%' OR \"Process CommandLine\" ILIKE '%netsh%portproxy%' OR \"Process CommandLine\" ILIKE '%certutil%urlcache%' LAST 7 DAYS",
        },
    },
    "cloud_identity": {
        "name": "Cloud & Identity Attacks",
        "icon": "☁️",
        "color": "#10b981",
        "keywords": ["cloud", "aws", "azure", "entra", "microsoft 365", "m365", "okta", "snowflake", "saas",
                     "oauth", "token theft", "mfa bypass", "mfa fatigue", "s3 bucket", "misconfigured",
                     "exposed database", "api key", "access key", "identity provider", "sso", "salesforce",
                     "kubernetes", "container", "account takeover", "credential stuffing", "password spray"],
        "summary": "Attackers abuse stolen credentials, tokens and misconfigurations to access cloud "
                   "consoles and SaaS tenants, often without touching an endpoint.",
        "chain": [
            ("Credential Access", "Password spraying, credential stuffing, stolen session tokens, leaked keys.", ["T1110.003", "T1110.004", "T1528"]),
            ("Initial Access", "Log in with valid cloud accounts; MFA fatigue / device-code phishing.", ["T1078.004", "T1621"]),
            ("Persistence", "Create new access keys, service principals, federated trusts.", ["T1098.001", "T1136.003", "T1484.002"]),
            ("Discovery", "Enumerate storage, IAM roles, SaaS records.", ["T1580", "T1526", "T1619"]),
            ("Exfiltration / Impact", "Download data stores, crypto-mine, extort.", ["T1530", "T1537", "T1496"]),
        ],
        "detection": [
            "Many failed logins across many accounts from one IP (spray)",
            "New access keys / service principal credentials created",
            "Impossible travel; sign-ins from VPS/Tor ranges",
            "Bulk downloads / exports from SaaS (Salesforce, Snowflake)",
        ],
        "mitigations": [
            "Enforce MFA everywhere incl. service accounts; block legacy auth",
            "Rotate and vault keys; prefer workload identity over static keys",
            "CSPM to detect public buckets / databases",
            "Conditional access: compliant device + location policies",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK"\n| match: principal.ip over 1h\n| outcome: $users = count_distinct(target.user.userid)\n| condition: $users > 15',
            "splunk": 'index=* (sourcetype="azure:aad:signin" OR sourcetype="o365:management:activity" OR sourcetype="aws:cloudtrail") (ResultType!=0 OR errorCode=*)\n| stats dc(user) as users count by src_ip\n| where users > 15',
            "sentinel": 'SigninLogs\n| where ResultType != 0\n| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 1h)\n| where Users > 15',
            "elastic": 'event.category : "authentication" and event.outcome : "failure"  // then aggregate by source.ip with distinct user.name > 15',
            "qradar": "SELECT sourceip, UNIQUECOUNT(username) AS users, COUNT(*) AS attempts FROM events WHERE CATEGORYNAME(category) ILIKE '%Authentication Failed%' GROUP BY sourceip HAVING users > 15 LAST 24 HOURS",
        },
    },
    "botnet_ddos": {
        "name": "Botnets & DDoS",
        "icon": "🌐",
        "color": "#f97316",
        "keywords": ["botnet", "ddos", "denial of service", "mirai", "iot malware", "router", "proxy botnet",
                     "residential proxy", "amplification", "hacktivist", "noname057", "layer 7", "dos attack"],
        "summary": "Compromised IoT devices and servers are enlisted into botnets used for DDoS, "
                   "proxying malicious traffic and spreading malware.",
        "chain": [
            ("Initial Access", "Exploit IoT/router CVEs or default credentials at scale.", ["T1190", "T1110.001"]),
            ("Execution & Persistence", "Download bot binary for the device architecture; cron persistence.", ["T1105", "T1053.003"]),
            ("Command & Control", "Connect to C2 over IRC/HTTP/custom protocols, DGA domains.", ["T1071", "T1568.002"]),
            ("Impact", "Launch volumetric / application-layer DDoS, or sell as proxy network.", ["T1498", "T1499", "T1090"]),
        ],
        "detection": [
            "Outbound connections to known C2 IPs (Feodo/ThreatFox lists)",
            "Sudden spikes of inbound traffic by single URI / user-agent",
            "IoT devices making outbound SSH/Telnet scans",
        ],
        "mitigations": [
            "Change default creds, patch/replace EoL IoT devices",
            "DDoS protection / WAF rate-limiting",
            "Egress filtering and blocklists for C2 infrastructure",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "NETWORK_CONNECTION" AND network.direction = "OUTBOUND" AND (target.port = 23 OR target.port = 2323 OR target.port = 7547 OR target.port = 37215 OR target.port = 52869)',
            "splunk": 'index=* (sourcetype=firewall OR tag=network) dest_port IN (23,2323,7547,37215,52869) direction=outbound\n| stats dc(dest_ip) as targets by src_ip | where targets > 50',
            "sentinel": 'CommonSecurityLog\n| where DestinationPort in (23, 2323, 7547, 37215, 52869)\n| summarize Targets = dcount(DestinationIP) by SourceIP, bin(TimeGenerated, 1h)\n| where Targets > 50',
            "elastic": 'destination.port : (23 or 2323 or 7547 or 37215 or 52869) and network.direction : "outbound"',
            "qradar": "SELECT sourceip, UNIQUECOUNT(destinationip) AS targets FROM flows WHERE destinationport IN (23,2323,7547,37215,52869) GROUP BY sourceip HAVING targets > 50 LAST 1 HOURS",
        },
    },
    "data_breach": {
        "name": "Data Breach & Leak",
        "icon": "💾",
        "color": "#64748b",
        "keywords": ["data breach", "breach", "leak", "leaked", "exposed", "stolen data", "records",
                     "customer data", "personal information", "pii", "dark web", "hacked", "compromised data",
                     "data theft", "class action"],
        "summary": "Unauthorized access leads to theft or exposure of customer and employee data, "
                   "often discovered when data appears on leak sites or forums.",
        "chain": [
            ("Initial Access", "Exploited app, stolen credentials, third-party vendor compromise.", ["T1190", "T1078", "T1199"]),
            ("Discovery", "Locate databases, file shares and SaaS data stores.", ["T1083", "T1213"]),
            ("Collection", "Query/dump databases, archive files.", ["T1005", "T1560"]),
            ("Exfiltration", "Exfiltrate via HTTPS / cloud storage; post on forums.", ["T1567", "T1048"]),
        ],
        "detection": [
            "Large database exports / unusual SELECT * volume",
            "Outbound data volume anomalies per host",
            "Access to sensitive shares by service accounts outside baseline",
        ],
        "mitigations": [
            "Data classification + DLP on egress",
            "Least privilege on databases; monitor bulk reads",
            "Third-party risk reviews; contractual breach notification",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "NETWORK_CONNECTION" AND network.direction = "OUTBOUND"\n| match: principal.hostname over 1h\n| outcome: $bytes = sum(network.sent_bytes)\n| condition: $bytes > 1000000000',
            "splunk": 'index=* tag=network direction=outbound\n| stats sum(bytes_out) as bytes by src_ip dest\n| where bytes > 1000000000 | sort - bytes',
            "sentinel": 'CommonSecurityLog\n| summarize Bytes = sum(SentBytes) by SourceIP, DestinationHostName, bin(TimeGenerated, 1h)\n| where Bytes > 1000000000\n| order by Bytes desc',
            "elastic": 'network.direction : "outbound"  // aggregate sum(source.bytes) by source.ip > 1GB/hour',
            "qradar": "SELECT sourceip, destinationip, SUM(sourcebytes) AS bytes FROM flows GROUP BY sourceip, destinationip HAVING bytes > 1000000000 LAST 1 HOURS",
        },
    },
    "ai_llm": {
        "name": "AI / LLM Threats",
        "icon": "🤖",
        "color": "#a855f7",
        "keywords": ["prompt injection", "llm", "large language model", "ai agent", "chatgpt", "copilot",
                     "gemini", "claude", "model context protocol", "mcp server", "deepfake", "ai-powered",
                     "generative ai", "genai", "jailbreak", "ai model", "machine learning", "agentic"],
        "summary": "Abuse of AI systems: prompt injection against agents, data leakage through LLM "
                   "integrations, malicious MCP servers/plugins, and AI-generated phishing/deepfakes.",
        "chain": [
            ("Reconnaissance", "Discover exposed AI endpoints, agents and tools they can call.", ["AML.T0000", "T1595"]),
            ("Initial Access", "Indirect prompt injection via documents, emails, web pages or tool output.", ["AML.T0051"]),
            ("Execution", "Agent executes attacker instructions using its tools/permissions.", ["AML.T0053"]),
            ("Exfiltration", "Leak data via rendered links, tool calls or responses.", ["AML.T0057", "AML.T0024"]),
        ],
        "detection": [
            "Agent tool calls to unexpected external domains",
            "Prompts containing instruction-override patterns in ingested content",
            "Unusual volume of API calls from AI service accounts",
        ],
        "mitigations": [
            "Least-privilege tool permissions; human approval for sensitive actions",
            "Treat retrieved content as untrusted; output filtering",
            "Allow-list MCP servers/plugins; review OWASP LLM Top 10 & MITRE ATLAS",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "NETWORK_HTTP" AND principal.user.userid = /svc[-_]?(ai|llm|agent|copilot)/ nocase AND NOT target.hostname = /(openai\\.com|anthropic\\.com|googleapis\\.com|azure\\.com)$/',
            "splunk": 'index=proxy user="svc*ai*" OR user="svc*agent*"\n| stats count by user dest | where NOT match(dest,"(openai|anthropic|googleapis|azure)\\.com$")',
            "sentinel": 'CommonSecurityLog\n| where SourceUserName matches regex @"(?i)svc[-_]?(ai|llm|agent)"\n| where DestinationHostName !endswith "openai.com" and DestinationHostName !endswith "anthropic.com"\n| summarize count() by SourceUserName, DestinationHostName',
            "elastic": 'user.name : (*ai* or *agent* or *llm*) and not destination.domain : (*openai.com or *anthropic.com or *googleapis.com)',
            "qradar": "SELECT username, \"URL Host\", COUNT(*) FROM events WHERE username ILIKE 'svc%agent%' GROUP BY username, \"URL Host\" LAST 24 HOURS",
        },
    },
    "mobile": {
        "name": "Mobile Malware & Spyware",
        "icon": "📱",
        "color": "#14b8a6",
        "keywords": ["android", "ios", "iphone", "mobile malware", "spyware", "pegasus", "apk", "banking app",
                     "google play", "app store", "sms", "stalkerware", "predator spyware"],
        "summary": "Malicious or trojanized apps and zero-click exploits target smartphones to steal "
                   "credentials, OTPs and messages, or to surveil specific individuals.",
        "chain": [
            ("Initial Access", "Smishing link to malicious APK, trojanized store app, or zero-click exploit.", ["T1660", "T1474"]),
            ("Privilege Escalation", "Abuse accessibility services / device admin; kernel exploits.", ["T1626", "T1404"]),
            ("Collection", "Read SMS/OTP, overlay banking apps, record audio/screen.", ["T1636.004", "T1417", "T1513"]),
            ("Exfiltration", "Send data to C2 over HTTPS / Firebase.", ["T1646"]),
        ],
        "detection": [
            "MDM alerts for side-loaded apps or accessibility abuse",
            "Mobile devices contacting known C2 domains",
        ],
        "mitigations": [
            "MDM with app allow-listing; block side-loading",
            "Lockdown Mode for high-risk users; prompt OS updates",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "NETWORK_DNS" AND principal.asset.platform_software.platform = "ANDROID"',
            "splunk": 'index=mdm (alert_type="sideloaded_app" OR alert_type="accessibility_abuse") | stats count by device user app',
            "sentinel": 'DeviceInfo\n| where OSPlatform in ("Android","iOS")\n| join kind=inner (DeviceNetworkEvents) on DeviceId',
            "elastic": 'host.os.type : ("android" or "ios") and event.category : "network"',
            "qradar": "SELECT sourceip, \"Device Type\", COUNT(*) FROM events WHERE \"Device Type\" IN ('Android','iOS') GROUP BY sourceip, \"Device Type\" LAST 24 HOURS",
        },
    },
    "web_app": {
        "name": "Web Application Attacks",
        "icon": "🧩",
        "color": "#eab308",
        "keywords": ["sql injection", "sqli", "cross-site scripting", "xss", "csrf", "ssrf", "path traversal",
                     "directory traversal", "deserialization", "file upload", "wordpress", "plugin",
                     "command injection", "xxe", "idor", "broken access control", "magecart", "skimmer"],
        "summary": "Flaws in web applications (injection, broken access control, insecure upload/deserialization) "
                   "let attackers read data, take over accounts or execute code on the server.",
        "chain": [
            ("Reconnaissance", "Crawl and fuzz parameters; fingerprint CMS/plugins.", ["T1595.003", "T1592"]),
            ("Initial Access", "Exploit SQLi, SSRF, upload or deserialization bugs.", ["T1190"]),
            ("Persistence", "Upload web shell; inject JS skimmer.", ["T1505.003"]),
            ("Collection / Impact", "Dump DB tables, steal card data, deface.", ["T1005", "T1491.002"]),
        ],
        "detection": [
            "WAF alerts for injection payloads (UNION SELECT, ../, ${jndi:)",
            "HTTP 200 responses to requests containing attack strings",
            "New .php/.jsp/.aspx files in upload directories",
        ],
        "mitigations": [
            "Parameterised queries, input validation (OWASP ASVS)",
            "WAF with virtual patching; keep CMS/plugins updated",
            "Least privilege DB accounts; CSP headers",
        ],
        "behaviour": {
            "secops": 'metadata.event_type = "NETWORK_HTTP" AND target.url = /(union(\\s|%20|\\+)+select|\\.\\.\\/|%2e%2e%2f|\\$\\{jndi:|<script|sleep\\(\\d+\\))/ nocase',
            "splunk": 'index=web (sourcetype=access_combined OR sourcetype=iis)\n| regex uri_query="(?i)(union(\\s|%20|\\+)+select|\\.\\./|%2e%2e%2f|\\$\\{jndi:|<script|sleep\\(\\d+\\))"\n| stats count by clientip uri_path status',
            "sentinel": 'W3CIISLog\n| where csUriQuery matches regex @"(?i)(union(\\s|%20|\\+)+select|\\.\\./|%2e%2e%2f|\\$\\{jndi:|<script|sleep\\(\\d+\\))"\n| summarize count() by cIP, csUriStem, scStatus',
            "elastic": 'url.query : (*union*select* or *..%2f* or *jndi* or *script*)',
            "qradar": "SELECT sourceip, URL, COUNT(*) FROM events WHERE URL ILIKE '%union%select%' OR URL ILIKE '%../%' OR URL ILIKE '%jndi:%' GROUP BY sourceip, URL LAST 24 HOURS",
        },
    },
    "vulnerability": {
        "name": "Vulnerability Disclosure",
        "icon": "🐞",
        "color": "#0ea5e9",
        "keywords": ["vulnerability", "vulnerabilities", "cve-", "patch", "security update", "flaw", "bug",
                     "patch tuesday", "advisory", "privilege escalation", "buffer overflow", "out-of-bounds"],
        "summary": "Newly disclosed vulnerabilities and patches. Prioritise by exploitation status "
                   "(CISA KEV), EPSS probability and exposure of the affected product.",
        "chain": [
            ("Weaponization", "Researchers/attackers diff patches and publish PoCs.", ["T1588.005", "T1587.004"]),
            ("Exploitation", "Exploit public-facing or client-side vulnerability.", ["T1190", "T1203"]),
            ("Privilege Escalation", "Local exploit for SYSTEM/root.", ["T1068"]),
        ],
        "detection": [
            "Vulnerability scanner findings for the CVE on exposed assets",
            "IDS/WAF signatures released by vendors for the CVE",
        ],
        "mitigations": [
            "Patch by risk: KEV > high EPSS > CVSS",
            "Compensating controls (WAF rules, disabling feature) until patched",
        ],
        "behaviour": {},
    },
}

GENERIC_PATTERN = "vulnerability"

# --------------------------------------------------------------------------
# Industries
# --------------------------------------------------------------------------
INDUSTRIES = {
    "Healthcare": ["hospital", "healthcare", "health care", "medical", "clinic", "patient", "pharma", "pharmaceutical", "health system", "nhs", "biotech"],
    "Finance": ["bank", "banking", "financial", "finance", "fintech", "credit union", "insurance", "insurer", "payment", "crypto exchange", "cryptocurrency", "stock exchange", "brokerage", "swift"],
    "Government": ["government", "ministry", "federal", "municipal", "city of", "county", "agency", "parliament", "embassy", "public sector", "state department", "diplomatic"],
    "Defense": ["defense", "defence", "military", "armed forces", "army", "navy", "aerospace", "missile"],
    "Education": ["university", "school", "college", "education", "student", "academic", "k-12"],
    "Energy & Utilities": ["energy", "oil", "gas pipeline", "power grid", "electric", "utility", "utilities", "water treatment", "nuclear", "solar", "ics", "scada", "ot network", "operational technology"],
    "Manufacturing": ["manufacturing", "manufacturer", "factory", "industrial", "automotive", "car maker", "semiconductor"],
    "Telecommunications": ["telecom", "telecommunications", "carrier", "isp", "mobile operator", "5g", "broadband"],
    "Retail & E-commerce": ["retail", "retailer", "e-commerce", "ecommerce", "online store", "shopping", "magento", "woocommerce", "point-of-sale", "pos malware"],
    "Technology": ["software", "saas", "cloud provider", "tech company", "it services", "managed service provider", "msp", "developer", "open source", "github", "npm", "pypi"],
    "Transportation & Logistics": ["airline", "airport", "aviation", "shipping", "logistics", "maritime", "port of", "railway", "transport"],
    "Media & Entertainment": ["media", "news outlet", "broadcaster", "gaming", "game", "streaming", "entertainment"],
    "Hospitality": ["hotel", "hospitality", "travel", "booking", "casino", "restaurant"],
    "Legal & Professional": ["law firm", "legal", "accounting", "consulting"],
    "Critical Infrastructure": ["critical infrastructure"],
}

# --------------------------------------------------------------------------
# Regions (country / demonym -> region)
# --------------------------------------------------------------------------
REGIONS = {
    "North America": ["united states", "u.s.", "us-based", "usa", "america", "american", "canada", "canadian", "mexico", "fbi", "cisa", "nsa"],
    "Europe": ["europe", "european", "eu ", "uk", "united kingdom", "britain", "british", "germany", "german", "france", "french", "italy", "italian", "spain", "spanish", "netherlands", "dutch", "poland", "polish", "ukraine", "ukrainian", "sweden", "norway", "finland", "denmark", "belgium", "switzerland", "austria", "ireland", "czech", "romania", "europol", "ncsc"],
    "Russia & CIS": ["russia", "russian", "belarus", "kazakhstan", "moscow"],
    "Middle East": ["israel", "israeli", "iran", "iranian", "saudi", "uae", "emirates", "qatar", "middle east", "turkey", "turkish", "jordan", "iraq", "egypt"],
    "South Asia": ["india", "indian", "pakistan", "pakistani", "bangladesh", "sri lanka", "nepal", "cert-in"],
    "East Asia": ["china", "chinese", "japan", "japanese", "korea", "korean", "taiwan", "taiwanese", "hong kong", "beijing", "north korea", "dprk"],
    "Southeast Asia": ["singapore", "indonesia", "malaysia", "philippines", "vietnam", "thailand", "myanmar", "cambodia"],
    "Oceania": ["australia", "australian", "new zealand"],
    "Latin America": ["brazil", "brazilian", "argentina", "chile", "colombia", "peru", "latin america", "latam"],
    "Africa": ["africa", "african", "nigeria", "kenya", "south africa", "morocco", "ghana"],
}

# --------------------------------------------------------------------------
# ATT&CK technique names (subset used in playbooks; MITRE collector adds more)
# --------------------------------------------------------------------------
TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application", "T1078": "Valid Accounts", "T1078.004": "Cloud Accounts",
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service", "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell", "T1059.006": "Python", "T1059.007": "JavaScript", "T1543.003": "Windows Service",
    "T1053.005": "Scheduled Task", "T1053.003": "Cron", "T1136": "Create Account", "T1136.003": "Cloud Account",
    "T1219": "Remote Access Software", "T1003.001": "LSASS Memory", "T1003.003": "NTDS", "T1003.006": "DCSync",
    "T1558.003": "Kerberoasting", "T1087.002": "Domain Account Discovery", "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol", "T1021.002": "SMB/Windows Admin Shares", "T1047": "WMI",
    "T1562": "Impair Defenses", "T1562.001": "Disable or Modify Tools", "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs", "T1068": "Exploitation for Privilege Escalation",
    "T1560": "Archive Collected Data", "T1560.001": "Archive via Utility", "T1567": "Exfiltration Over Web Service",
    "T1567.002": "Exfiltration to Cloud Storage", "T1490": "Inhibit System Recovery", "T1486": "Data Encrypted for Impact",
    "T1589.002": "Email Addresses", "T1591.004": "Identify Roles", "T1583.001": "Domains", "T1608.005": "Link Target",
    "T1608.006": "SEO Poisoning", "T1204.001": "Malicious Link", "T1204.002": "Malicious File", "T1557": "Adversary-in-the-Middle",
    "T1539": "Steal Web Session Cookie", "T1111": "Multi-Factor Authentication Interception",
    "T1098.005": "Device Registration", "T1098.001": "Additional Cloud Credentials", "T1564.008": "Email Hiding Rules",
    "T1550.001": "Application Access Token", "T1534": "Internal Spearphishing", "T1657": "Financial Theft",
    "T1595": "Active Scanning", "T1595.002": "Vulnerability Scanning", "T1595.003": "Wordlist Scanning",
    "T1592": "Gather Victim Host Information", "T1592.002": "Software", "T1505.003": "Web Shell",
    "T1552.001": "Credentials In Files", "T1552.004": "Private Keys", "T1555": "Credentials from Password Stores",
    "T1555.003": "Credentials from Web Browsers", "T1195.001": "Compromise Software Dependencies",
    "T1195.002": "Compromise Software Supply Chain", "T1586": "Compromise Accounts", "T1041": "Exfiltration Over C2 Channel",
    "T1189": "Drive-by Compromise", "T1055": "Process Injection", "T1027": "Obfuscated Files or Information",
    "T1113": "Screen Capture", "T1005": "Data from Local System", "T1082": "System Information Discovery",
    "T1589": "Gather Victim Identity Information", "T1593": "Search Open Websites/Domains", "T1199": "Trusted Relationship",
    "T1542": "Pre-OS Boot", "T1218": "System Binary Proxy Execution", "T1090": "Proxy", "T1090.003": "Multi-hop Proxy",
    "T1046": "Network Service Discovery", "T1114": "Email Collection", "T1114.002": "Remote Email Collection",
    "T1048": "Exfiltration Over Alternative Protocol", "T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
    "T1110.004": "Credential Stuffing", "T1528": "Steal Application Access Token", "T1621": "MFA Request Generation",
    "T1484.002": "Trust Modification", "T1580": "Cloud Infrastructure Discovery", "T1526": "Cloud Service Discovery",
    "T1619": "Cloud Storage Object Discovery", "T1530": "Data from Cloud Storage", "T1537": "Transfer Data to Cloud Account",
    "T1496": "Resource Hijacking", "T1105": "Ingress Tool Transfer", "T1071": "Application Layer Protocol",
    "T1568.002": "Domain Generation Algorithms", "T1498": "Network Denial of Service", "T1499": "Endpoint Denial of Service",
    "T1083": "File and Directory Discovery", "T1213": "Data from Information Repositories", "T1491.002": "External Defacement",
    "T1588.005": "Exploits", "T1587.004": "Exploits (Develop)", "T1203": "Exploitation for Client Execution",
    "T1660": "Phishing (Mobile)", "T1474": "Supply Chain Compromise (Mobile)", "T1626": "Abuse Elevation Control Mechanism",
    "T1404": "Exploitation for Privilege Escalation (Mobile)", "T1636.004": "SMS Messages", "T1417": "Input Capture",
    "T1513": "Screen Capture (Mobile)", "T1646": "Exfiltration Over C2 Channel (Mobile)",
    "AML.T0000": "Search for Victim's Publicly Available Research Materials", "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "LLM Plugin Compromise", "AML.T0057": "LLM Data Leakage", "AML.T0024": "Exfiltration via ML Inference API",
}

# Common D3FEND countermeasures per ATT&CK tactic stage (for "how to defend")
D3FEND_HINTS = {
    "Initial Access": ["D3-NTA Network Traffic Analysis", "D3-MFA Multi-factor Authentication", "D3-SU Software Update"],
    "Execution": ["D3-EAL Executable Allowlisting", "D3-PSA Process Spawn Analysis"],
    "Persistence": ["D3-SCH Scheduled Job Analysis", "D3-SDA Service Dependency Analysis"],
    "Credential Access": ["D3-CH Credential Hardening", "D3-PH Process Hardening (LSA protection)"],
    "Lateral Movement": ["D3-NI Network Isolation", "D3-RTSD Remote Terminal Session Detection"],
    "Defense Evasion": ["D3-PLA Process Lineage Analysis", "D3-SFA System File Analysis"],
    "Exfiltration": ["D3-OTF Outbound Traffic Filtering", "D3-NTCD Network Traffic Community Deviation"],
    "Impact": ["D3-FBA File Backup", "D3-FEV File Eviction"],
    "Reconnaissance": ["D3-DNSDL DNS Denylisting", "D3-ISVA Inbound Session Volume Analysis"],
    "Command & Control": ["D3-DNSTA DNS Traffic Analysis", "D3-ITF Inbound Traffic Filtering"],
}

# Reference toolkit (shown in UI)
TOOLKIT = [
    {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "desc": "Track actively exploited vulnerabilities", "cat": "Vulnerabilities", "ingested": True},
    {"name": "NVD", "url": "https://nvd.nist.gov", "desc": "Inspect CVEs and risk data", "cat": "Vulnerabilities", "ingested": True},
    {"name": "FIRST EPSS", "url": "https://www.first.org/epss", "desc": "Estimate CVE exploit probability", "cat": "Vulnerabilities", "ingested": True},
    {"name": "MITRE ATT&CK", "url": "https://attack.mitre.org", "desc": "Map adversary tactics & techniques", "cat": "Frameworks", "ingested": True},
    {"name": "MITRE D3FEND", "url": "https://d3fend.mitre.org", "desc": "Explore defensive techniques", "cat": "Frameworks", "ingested": False},
    {"name": "MITRE ATLAS", "url": "https://atlas.mitre.org", "desc": "Map attacks against AI systems", "cat": "Frameworks", "ingested": False},
    {"name": "MITRE CWE", "url": "https://cwe.mitre.org", "desc": "Study software weaknesses", "cat": "Frameworks", "ingested": False},
    {"name": "NIST CSF", "url": "https://www.nist.gov/cyberframework", "desc": "Structure cyber risk", "cat": "Frameworks", "ingested": False},
    {"name": "OWASP ASVS", "url": "https://owasp.org/www-project-application-security-verification-standard/", "desc": "App security requirements", "cat": "AppSec", "ingested": False},
    {"name": "OWASP GenAI", "url": "https://genai.owasp.org", "desc": "LLM and agent risks", "cat": "AppSec", "ingested": False},
    {"name": "PortSwigger Academy", "url": "https://portswigger.net/web-security", "desc": "Free web security labs", "cat": "Learning", "ingested": False},
    {"name": "picoCTF / CyLab", "url": "https://www.cylabacademy.org", "desc": "Free cybersecurity CTFs", "cat": "Learning", "ingested": False},
    {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "Decode / transform data", "cat": "Analysis", "ingested": False},
    {"name": "Wireshark", "url": "https://www.wireshark.org", "desc": "Inspect packet captures", "cat": "Analysis", "ingested": False},
    {"name": "Zeek", "url": "https://zeek.org", "desc": "Generate network security logs", "cat": "Analysis", "ingested": False},
    {"name": "SigmaHQ", "url": "https://sigmahq.io", "desc": "Shareable detection rules", "cat": "Detection", "ingested": False},
    {"name": "abuse.ch", "url": "https://abuse.ch", "desc": "Malware & IOC intelligence (ThreatFox, URLhaus, Feodo)", "cat": "IOCs", "ingested": True},
    {"name": "urlscan.io", "url": "https://urlscan.io", "desc": "Inspect site requests & redirects", "cat": "IOCs", "ingested": False},
    {"name": "Shodan", "url": "https://www.shodan.io", "desc": "Find internet-exposed services", "cat": "IOCs", "ingested": False},
    {"name": "SSL Labs", "url": "https://www.ssllabs.com/ssltest/", "desc": "Test HTTPS / TLS settings", "cat": "Analysis", "ingested": False},
    {"name": "AlienVault OTX", "url": "https://otx.alienvault.com", "desc": "Community threat pulses (needs free API key)", "cat": "IOCs", "ingested": True},
    {"name": "VirusTotal", "url": "https://www.virustotal.com", "desc": "File / URL / IP reputation", "cat": "IOCs", "ingested": False},
]
