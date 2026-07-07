---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are leveraging Microsoft's ClickOnce technology to deploy malware with minimal user interaction, bypass traditional security defenses, and establish persistence through built-in update mechanisms and strategic placement of `.appref-ms` files.
date: "2026-07-03T23:51:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - persistence
  - initial-access
  - windows
  - defense-evasion
  - malware
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
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
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
    evidence: every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) in a user's Startup folder, a known technique for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Executing ClickOnce .appref-ms
    description: Detects the creation of a scheduled task that executes a ClickOnce application shortcut (.appref-ms file), indicating potential persistence or execution via task scheduler.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology to facilitate malware delivery and achieve persistence on target systems, a technique highlighted in recent CrowdStrike research. This abuse capitalizes on the user-friendly nature of ClickOnce deployments, which require minimal interaction, often just a single click, and bypass common protection mechanisms like email filters. Crucially, ClickOnce applications do not require elevated privileges for installation, significantly lowering the barrier for attackers targeting standard user accounts. Adversaries can leverage legitimate Microsoft processes, such as `rundll32.exe` and `dfsvc.exe`, to execute malicious payloads stealthily. Furthermore, the built-in update mechanism of offline-configured ClickOnce applications, triggered by `.appref-ms` files, allows threat actors to maintain remote access and update their malware, including changing command and control (C2) addresses or delivering new malicious components, without further user prompts. This tactic presents a potent vector that security teams must actively monitor to prevent persistent footholds.

## Attack Chain

1.  **Initial Access**: The threat actor socially engineers a user into clicking a malicious link or opening a `.application` file, initiating the ClickOnce application deployment.
2.  **Execution & Installation**: Upon user interaction, the ClickOnce application installs with minimal user input and without requiring administrative privileges, executing a malicious payload within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`.
3.  **Persistence (Shortcut Creation)**: For applications configured to be available offline, an `.appref-ms` shortcut file is automatically dropped into the user's Start Menu folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence (Autostart)**: To ensure automatic execution, the threat actor places the malicious `.appref-ms` file into the Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to launch it.
5.  **Command and Control (Update Mechanism)**: When the `.appref-ms` file is opened (either manually by the user or automatically via persistence), it triggers an update check from the attacker-controlled deployment server.
6.  **Impact (Malware Update/Execution)**: The attacker pushes a malicious update, which is silently downloaded and executed upon application launch, effectively maintaining remote access and enabling further malicious actions such as data exfiltration or deploying additional malware.

## Impact

The abuse of ClickOnce technology allows threat actors to circumvent common security controls and establish persistent access with high stealth. If successful, this can lead to unauthorized execution of arbitrary code, silent deployment of evolving malware, and sustained remote access to victim systems. The lack of awareness around ClickOnce applications and their legitimacy in Microsoft process trees makes these attacks difficult to detect without specific monitoring. Organizations could face widespread compromise, data breaches, or ransomware infections, as the technique targets general users and requires minimal privileges, making enterprise endpoints particularly vulnerable.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable Sysmon file creation and process creation logging to activate the rules above.
*   Monitor for the creation or modification of `.appref-ms` files in the user's Startup folder as described in the `Detect ClickOnce .appref-ms Persistence in Startup Folder` rule.
*   Implement detection for scheduled tasks that execute `.appref-ms` files, as outlined in the `Detect Scheduled Task Executing ClickOnce .appref-ms` rule.
*   Educate users about the risks of clicking on unverified links or opening `.application` files, even if they appear to originate from legitimate sources.
