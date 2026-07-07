---
title: Threat Actors Abuse Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse-persistence
description: Threat actors are actively leveraging Microsoft's ClickOnce technology to achieve initial access, execute malicious payloads, and establish persistence on target systems by exploiting its minimal user interaction requirements and legitimate process execution, enabling defense evasion and C2 updates.
date: "2026-07-07T18:46:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - defense-evasion
  - windows
  - microsoft-technology
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: ""
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: ""
    evidence: By placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: ""
    evidence: or creating a scheduled task to process the file regularly
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: a built-in updating mechanism...to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Direct Execution of ClickOnce Application from User Directory
    description: Detects direct execution of the ClickOnce Deployment Support Service (dfsvc.exe) with a .application file from user-writable directories, a common abuse technique by threat actors to deploy malicious ClickOnce apps.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Creation of .appref-ms in User Startup Directories
    description: Detects the creation or modification of a ClickOnce shortcut (.appref-ms) file within a user's Windows Startup folder, a technique used by adversaries for persistence.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1036.003
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Scheduled Task Creation for .appref-ms File
    description: Detects the creation of a scheduled task that targets a ClickOnce shortcut file (.appref-ms), which can be used by adversaries for persistence through automated execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology as a versatile attack vector for initial access, execution, and persistence. This abuse is driven by several key factors: the user-friendly deployment process requires minimal interaction, often bypassing traditional email and endpoint security controls that heavily scrutinize `.exe` files. ClickOnce applications deploy without requiring elevated privileges, allowing adversaries to target standard user accounts. A significant advantage for attackers is the execution of malicious payloads within legitimate Microsoft process trees, specifically `rundll32.exe` and `dfsvc.exe`, increasing stealth and evading detection. Furthermore, the built-in update mechanism of ClickOnce allows attackers to maintain persistent access, update malware, modify Command and Control (C2) addresses, and facilitate lateral movement without needing further user interaction. The general lack of awareness around the security implications of ClickOnce apps among users and defenders further enhances the effectiveness of these attacks.

## Attack Chain

1.  **Initial Access**: Adversaries deliver a malicious ClickOnce application, typically via a web link or a standalone `.application` file, through social engineering tactics to a target user.
2.  **User Execution**: The target user is convinced to click the web link or execute the `.application` file, initiating the ClickOnce deployment process.
3.  **Deployment & Execution**: The ClickOnce application deploys, and its embedded malicious payload executes discreetly within legitimate Microsoft processes, such as `rundll32.exe` or `dfsvc.exe`.
4.  **Persistence - Shortcut**: If configured for offline availability, a malicious `.appref-ms` shortcut file is dropped in the user's Start Menu directory (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Persistence - Startup/Scheduled Task**: The attacker leverages the dropped `.appref-ms` file by placing it in a Windows Startup folder or creating a scheduled task to automatically launch it.
6.  **Command and Control (C2) via Updates**: The malicious ClickOnce application utilizes its inherent update mechanism to fetch new malicious components, change C2 server addresses, and facilitate lateral movement or other post-exploitation activities without requiring additional user prompting.

## Impact

The abuse of ClickOnce allows threat actors to bypass common protection mechanisms, leading to successful initial access and prolonged persistence within victim environments. While no specific victim counts or sectors were provided, the technique's effectiveness against "traditional defenses" suggests a broad targeting potential across various industries. If successful, attackers can establish reliable remote access, covertly update their malware, alter C2 communications, and move laterally across networks, leading to data exfiltration, ransomware deployment, or other detrimental outcomes. The stealthy nature of execution within legitimate Microsoft processes further complicates detection and incident response efforts, potentially leading to extended dwell times.

## Recommendation

*   Enable Sysmon process creation (Event ID 1), file creation (Event ID 11), and scheduled task creation (Event ID 12/13/14) logging to detect the behaviors described in this brief.
*   Deploy the "Direct Execution of ClickOnce Application from User Directory" Sigma rule to identify suspicious `dfsvc.exe` invocations.
*   Implement the "Creation of .appref-ms in User Startup Directories" Sigma rule to detect malicious persistence attempts via ClickOnce shortcut files.
*   Utilize the "Scheduled Task Creation for .appref-ms File" Sigma rule to identify scheduled persistence targeting ClickOnce applications.
*   Educate users on the risks associated with clicking suspicious links or executing `.application` files from untrusted sources, emphasizing that legitimate software installations typically involve more prominent prompts.
