---
title: Threat Actors Abuse Microsoft ClickOnce for Initial Access and Persistent Malware Deployment
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology for initial access, execution, and persistence by leveraging its user-friendly deployment and update mechanisms to deliver and maintain malware without elevated privileges, often bypassing traditional security defenses.
date: "2026-07-06T08:12:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - initial-access
  - persistence
  - defense-evasion
  - windows
  - malware
  - apt
vendors:
  - Microsoft
products:
  - ClickOnce Technology
  - ClickOnce applications
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by [...] creating a scheduled task
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence in Startup Folder
    description: Detects the creation of .appref-ms files in a user's Startup folder, a known technique for ClickOnce-based persistence (ATT&CK T1547.001).
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation for ClickOnce Appref-ms File
    description: Detects the creation of scheduled tasks that launch ClickOnce .appref-ms files, indicating a persistence mechanism (ATT&CK T1053.005).
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

CrowdStrike has observed threat actors actively exploiting Microsoft's ClickOnce technology, enabling them to achieve initial access, execute malicious payloads, and maintain persistence on target systems. This new abuse vector leverages ClickOnce's inherent design, which allows applications to be deployed with minimal user interaction and without requiring administrative privileges, thereby bypassing common security controls like email filters and traditional application whitelisting. Attackers coerce users into clicking malicious links or `.application` files, triggering the stealthy deployment of malware. The malicious code then executes within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, to evade detection. Furthermore, attackers exploit ClickOnce's built-in update mechanism to remotely update their malware, facilitating command and control (C2) changes, lateral movement, or other post-exploitation activities. Persistence is achieved by placing `.appref-ms` files in the Start Menu's Startup folder or by creating scheduled tasks.

## Attack Chain

1.  **Initial Access (User Execution)**: Threat actors social engineer victims into clicking a malicious link or downloading and opening an `.application` file that initiates a ClickOnce deployment.
2.  **Application Deployment (Execution)**: The ClickOnce application installs on the target system with minimal user interaction and without requiring administrator privileges, often bypassing traditional software installation prompts.
3.  **Payload Execution (Execution)**: The malicious payload embedded within the ClickOnce application executes, often within the process context of legitimate Microsoft binaries like `rundll32.exe` or `dfsvc.exe` to appear legitimate.
4.  **Persistence (Startup Folder)**: For applications configured to be available offline, a `.appref-ms` shortcut file is dropped in the user's Start Menu, specifically within `%APPDATA%\Microsoft\Windows\Start Menu\Programs\`, which attackers can place in the Startup folder for auto-execution upon logon.
5.  **Persistence (Scheduled Task)**: Alternatively, attackers create a scheduled task to automatically launch the `.appref-ms` file, ensuring the malicious ClickOnce application runs periodically or upon specific events.
6.  **Command and Control / Updates (C2)**: Threat actors leverage the ClickOnce application's built-in update mechanism to push new malicious components, modify command and control (C2) infrastructure, or facilitate further compromise like lateral movement.
7.  **Impact**: Ongoing remote access, data exfiltration, lateral movement, or further malicious activity, depending on the attacker's objectives.

## Impact

The abuse of ClickOnce technology leads to significant security implications, as it allows threat actors to establish persistent access and execute arbitrary code on enterprise endpoints without triggering common security alerts. The attacker's ability to operate without elevated privileges means standard user accounts, prevalent across organizations, are vulnerable. Once established, adversaries can leverage the built-in update mechanism to maintain remote access, pivot to lateral movement, or exfiltrate sensitive data. The stealthy execution within legitimate Microsoft processes further complicates detection, making these attacks particularly effective at bypassing endpoint defenses and achieving long-term compromise.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM/EDR to detect suspicious ClickOnce persistence mechanisms.
*   Monitor `file_event` logs for the creation of `.appref-ms` files within user Startup directories (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`).
*   Monitor `process_creation` logs for the execution of `schtasks.exe` or `powershell.exe` command lines that create scheduled tasks referencing `.appref-ms` files.
*   Educate users about the risks associated with clicking suspicious links or opening unsolicited `.application` files, even if they appear to originate from trusted sources.
*   Implement application whitelisting solutions that specifically control the execution of ClickOnce applications, treating them with the same scrutiny as traditional executables.
