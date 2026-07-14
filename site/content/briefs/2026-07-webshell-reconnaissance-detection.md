---
title: Webshell Reconnaissance Command Detection
slug: 2026-07-webshell-reconnaissance-detection
description: This brief describes detection of common reconnaissance commands executed through webshells on Windows systems, enabling defenders to identify post-exploitation discovery activities.
date: "2026-07-14T10:23:54Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:exclusiveaddons:exclusive_addons_for_elementor:*:*:*:*:*:wordpress:*:*
tags:
  - webshell
  - discovery
  - reconnaissance
  - attack.persistence
  - attack.discovery
  - attack.t1505.003
  - attack.t1018
  - attack.t1033
  - attack.t1087
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The rule's purpose is 'Webshell Detection With Command Line Keywords' and it detects commands executed by web server processes, implying a webshell is used for persistence.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Information Discovery
    evidence: The rule detects `systeminfo.exe`, `wmic.exe` (especially with `/node:`) which are used to gather system information.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The rule detects `net user`, `net group`, `whoami.exe`, `quser.exe`, and `dsquery.exe` which are used to enumerate accounts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Configuration Discovery
    evidence: The rule detects `ipconfig.exe` and `netstat.exe` which provide details on system network configurations.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: The rule detects `ping.exe -n`, `nslookup.exe`, `Test-NetConnection`, `tracert.exe` which are used to discover network services and connectivity.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
    evidence: The rule detects `tasklist.exe` which is used to list running processes.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The rule detects `schtasks.exe` which is used to query or manipulate scheduled tasks.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The rule detects `find.exe`, `findstr.exe`, and `dir \` patterns in command lines, used for locating files and directories.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule specifically looks for `powershell.exe` with command line arguments like `-enc`, `-EncodedCommand`, `-w hidden`, `-windowstyle hidden`, or `.WebClient).Download`.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule looks for `cmd.exe` executing various suspicious commands, which falls under Windows Command Shell execution.
    confidence_band: high
cves:
  - id: CVE-2024-1234
    cvss: 6.4
    epss: 0.01593
references:
  - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
  - https://unit42.paloaltonetworks.com/bumblebee-webshell-xhunt-campaign/
  - https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild
rules:
  - title: Webshell Detection With Command Line Keywords
    description: Detects suspicious command-line parameters and binary executions often used during reconnaissance activity via webshells, spawned by common web server processes.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
      - persistence
    techniques:
      - T1016
      - T1018
      - T1033
      - T1046
      - T1049
      - T1053.005
      - T1057
      - T1059.001
      - T1059.003
      - T1083
      - T1087
      - T1505.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief details a detection strategy for identifying post-exploitation reconnaissance activities performed via webshells on Windows servers. Attackers frequently deploy webshells on compromised web servers to maintain access and execute commands remotely. Following initial compromise, they typically employ various command-line utilities and scripting tools to gain a deeper understanding of the compromised system and network environment. This includes using tools like `net.exe`, `wmic.exe`, `ipconfig.exe`, `whoami.exe`, `schtasks.exe`, `systeminfo.exe`, and PowerShell with encoded commands. The detection focuses on processes spawned by common web server applications (e.g., IIS w3wp.exe, PHP-CGI, NGINX, Apache httpd, Tomcat Java processes) that then execute these suspicious discovery commands. Identifying such activity is crucial for early detection of an attacker's presence and preventing further compromise, lateral movement, or data exfiltration.

## Attack Chain

1. **Initial Access & Webshell Deployment**: An attacker exploits a vulnerability in a public-facing web application (e.g., CVE-2024-1234) to gain initial access and deploy a webshell (e.g., China Chopper, Bumblebee) onto the web server.
2. **Webshell Activation**: The attacker interacts with the deployed webshell, causing the legitimate web server process (e.g., `w3wp.exe`, `php-cgi.exe`, `java.exe` for Tomcat) to spawn a command-line interpreter (e.g., `cmd.exe`, `powershell.exe`).
3. **System Information Discovery**: The attacker executes commands like `systeminfo.exe` or `wmic.exe` (`wmic.exe os get caption /value`) to gather details about the operating system, hardware, and installed software, mapping the system's configuration.
4. **Network Configuration Discovery**: Commands such as `ipconfig.exe`, `netstat.exe`, `nslookup.exe`, `ping.exe`, `Test-NetConnection`, or `tracert.exe` are used to enumerate network interfaces, active connections, DNS information, and network connectivity to map the internal network segment.
5. **Account and User Discovery**: The attacker employs `whoami.exe`, `net user`, `net group`, `quser.exe`, or `dsquery.exe` to identify local and domain user accounts, groups, and logged-on users, seeking targets for privilege escalation or lateral movement.
6. **Process and Task Discovery**: `tasklist.exe` and `schtasks.exe` are executed to list running processes, services, and scheduled tasks, identifying potential running security software, interesting applications, or existing persistence mechanisms.
7. **File and Directory Discovery**: The attacker uses `find.exe`, `findstr.exe`, or `dir \\` (e.g., `dir \\<IP>\C$`) to search for sensitive files, configurations, or to explore remote shares for data or further access.
8. **Further Exploitation & Lateral Movement**: Based on the gathered reconnaissance, the attacker proceeds with privilege escalation, establishes additional persistence, moves laterally within the network, or prepares for data exfiltration.

## Impact

Successful execution of reconnaissance commands via a webshell indicates a significant compromise, potentially leading to immediate or future severe consequences. The attacker has established a persistent foothold, enabling them to map the network infrastructure, identify valuable assets, locate sensitive data, and enumerate user accounts. This intelligence gathering is a critical precursor to privilege escalation, lateral movement to other systems, data exfiltration, or the deployment of additional malicious payloads such as ransomware. Organizations could face severe data breaches, service disruption, reputational damage, and significant financial losses if these post-exploitation activities are not detected and remediated promptly. The presence of a webshell on a public-facing server poses an ongoing risk until completely eradicated.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune for your environment to detect webshell reconnaissance activities.
* Ensure comprehensive `process_creation` logging (e.g., Sysmon Event ID 1) is enabled on all Windows web servers to capture the necessary command-line arguments and parent-child process relationships for the rule.
* Regularly review logs for processes spawned by web server applications that execute unusual or discovery-related commands.
* Patch known vulnerabilities in web server software immediately to prevent webshell deployment.
