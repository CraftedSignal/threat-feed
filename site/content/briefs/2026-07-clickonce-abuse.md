---
title: New Abuse of ClickOnce Technology for Stealthy Persistence and Execution
slug: 2026-07-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce deployment technology, particularly `.application` and `.appref-ms` files, to achieve initial access, stealthy execution within legitimate Microsoft processes, and persistence by leveraging its built-in update mechanism and placing reference files in auto-start locations, bypassing traditional security controls and maintaining remote access.
date: "2026-07-05T07:33:02Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening... by placing a .appref-ms file in the Startup folder.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening... creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
iocs:
  - type: file_extension
    value: .application
  - type: file_extension
    value: .appref-ms
  - type: process
    value: rundll32.exe
  - type: process
    value: dfsvc.exe
  - type: path
    value: '%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'
ioc_counts:
  file_extension: 2
  path: 1
  process: 2
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of .appref-ms files within user Startup folders, a known persistence mechanism used by threat actors abusing ClickOnce.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are increasingly abusing Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to establish a persistent and stealthy presence on targeted systems. This "new abuse," identified by CrowdStrike, takes advantage of ClickOnce's user-friendly installation process, which often requires minimal user interaction and operates without elevated privileges. Attackers entice users to click misleading web buttons or open malicious `.application` files, initiating a deployment that drops `.appref-ms` files. These files are then used for persistence, for instance, by placing them in the Startup folder or linking them to scheduled tasks. This method allows malicious payloads to execute within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, effectively evading detection and providing a reliable channel for updating malware, changing command and control (C2) addresses, or facilitating lateral movement. The general lack of awareness regarding ClickOnce's security implications contributes to its effectiveness as an attack vector.

## Attack Chain

1.  **Initial Access**: Threat actor socially engineers a user into clicking a deceptive webpage button or opening a malicious `.application` file delivered via email or download.
2.  **Execution (Deployment)**: User interaction triggers the ClickOnce deployment process, which installs the seemingly benign or malicious application without requiring administrator privileges.
3.  **Persistence (File Drop)**: The deployed ClickOnce application drops an `.appref-ms` file, a shortcut to the application, typically in the Start Menu folder for offline availability.
4.  **Defense Evasion / Execution**: Malicious payloads within the ClickOnce application execute stealthily, leveraging legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe` to blend in with normal system activity.
5.  **Persistence (Autostart)**: The attacker strategically places the `.appref-ms` file in the Windows Startup folder or creates a scheduled task to automatically open it during boot or logon.
6.  **Persistence (Update Mechanism)**: Upon execution via the `.appref-ms` file, ClickOnce attempts to fetch updates from a server controlled by the threat actor, often without user prompt.
7.  **Command & Control / Impact**: The threat actor pushes malicious updates through the ClickOnce mechanism, allowing them to modify malware, update C2 addresses, facilitate lateral movement, or exfiltrate data.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common enterprise security controls and establish persistent access to compromised systems. By leveraging legitimate Microsoft processes, attackers achieve a high degree of stealth, making detection challenging. Successful exploitation can lead to unauthorized code execution, remote access to internal networks, ongoing malware updates for evolving C2 and lateral movement, and ultimately, significant data exfiltration or system compromise. The low privilege requirement for ClickOnce deployment broadens the attack surface to include standard user accounts, increasing the potential for widespread impact across an organization.

## Recommendation

*   Enable comprehensive process creation logging (e.g., via Sysmon) to monitor for suspicious activity involving `dfsvc.exe` and `rundll32.exe` with unusual command-line arguments or parent processes.
*   Deploy the Sigma rule "Detect ClickOnce `.appref-ms` Persistence in Startup Folder" to your SIEM to alert on unauthorized `.appref-ms` file creation in system autostart locations.
*   Educate users on the risks associated with opening `.application` files from untrusted sources or clicking suspicious web links, referencing the initial access techniques described in the brief.
*   Monitor for network connections initiated by `dfsvc.exe` and `rundll32.exe` to unusual or unapproved external domains, as this may indicate an active command and control channel.
