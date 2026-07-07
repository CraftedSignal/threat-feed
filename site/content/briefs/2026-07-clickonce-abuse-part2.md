---
title: New Abuse of ClickOnce Technology for Persistent Malware Delivery
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to deliver and persist malware, bypassing common defenses and achieving remote access through legitimate update mechanisms within standard user contexts.
date: "2026-07-05T08:08:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of .appref-ms files in the Windows Startup folder, a known method for achieving persistence with ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task Creation
    description: Detects scheduled tasks being created that are configured to execute .appref-ms files, indicating a ClickOnce persistence mechanism.
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

Threat actors are increasingly weaponizing Microsoft's ClickOnce technology for stealthy malware delivery and persistence, as detailed by CrowdStrike. This abuse leverages ClickOnce's user-friendly deployment, which requires minimal user interaction and often bypasses traditional security tools like mailbox filters. A significant aspect of this technique is that ClickOnce applications do not require elevated privileges for deployment, allowing attackers to target standard user accounts. Attackers also exploit ClickOnce's built-in update mechanism, pushing malicious updates through controlled deployment servers. This new abuse, particularly involving `.appref-ms` files, allows attackers to maintain remote access and modify command and control (C2) infrastructure by updating the application without user authorization, all while executing within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. This presents a powerful attack vector that requires active monitoring and defense.

## Attack Chain

1.  **Initial Access**: Threat actors convince a target user to click a deceptive link or button, initiating the deployment of a ClickOnce application.
2.  **Execution**: The ClickOnce application is deployed and executed, running within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, which helps evade detection.
3.  **Persistence (Initial)**: The deployed ClickOnce application drops an `.appref-ms` file in the user's Start Menu, enabling offline access and update checks.
4.  **Defense Evasion**: The malicious payload executes under legitimate Microsoft processes and the deployment process uses a genuine Microsoft user interface, making it difficult for users and some security tools to identify as malicious.
5.  **Persistence (Update Mechanism)**: The attacker, controlling the deployment server, pushes a malicious update to the seemingly benign ClickOnce application.
6.  **Command and Control / Execution (Updated)**: The next time the user launches the ClickOnce application via its `.appref-ms` shortcut, the malicious update is downloaded and executed without further user authorization, allowing the attacker to establish C2, exfiltrate data, or move laterally.
7.  **Persistence (Enhanced)**: To ensure consistent execution, the attacker places the `.appref-ms` file into the Windows Startup folder or creates a scheduled task to automatically launch it.
8.  **Impact**: The malicious ClickOnce application provides persistent remote access to the compromised system, allowing for further payload delivery, lateral movement, and data exfiltration under the guise of legitimate system activity.

## Impact

The abuse of ClickOnce technology leads to successful malware execution and long-term persistence on targeted systems. Attackers can gain and maintain remote access, update their malicious payloads to adapt command and control (C2) infrastructure, and potentially facilitate lateral movement and data exfiltration. This technique specifically targets standard user accounts, which comprise the majority of enterprise endpoints, thus broadening the attack surface. The stealthiness afforded by executing within legitimate Microsoft processes increases the likelihood of prolonged compromise, leading to significant data breaches or system disruption if not detected promptly.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable Sysmon process-creation and file-creation logging to detect `.appref-ms` files created in unusual locations or scheduled tasks launching them.
*   Educate end-users about the risks associated with clicking on unknown links or deploying applications, even if they appear to originate from legitimate sources or involve minimal prompts.
*   Monitor for process execution of `rundll32.exe` and `dfsvc.exe` with command-line arguments that reference `.application` or `.appref-ms` files, especially if initiated by unexpected parent processes.
