---
title: New Abuse of ClickOnce Technology for Stealthy Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part-2
description: CrowdStrike details how threat actors are weaponizing Microsoft's ClickOnce technology to deliver and maintain persistent access for malware on Windows systems without requiring administrative privileges, bypassing traditional defenses and leveraging legitimate processes for stealthy execution.
date: "2026-07-06T07:33:09Z"
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
  - malware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism...every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce AppRef-ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms shortcut file within a user's Startup folder, indicating a persistence mechanism via legitimate system paths.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation Referencing ClickOnce AppRef-ms
    description: Detects the creation of a new scheduled task that executes a ClickOnce .appref-ms file, a known persistence technique leveraged by threat actors.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has identified a new method of abusing Microsoft's ClickOnce technology, building on previously known techniques, to deliver and persist malware on target systems without requiring administrative privileges. Threat actors leverage ClickOnce's user-friendly deployment, which bypasses traditional security controls like email filters and deceives users into initiating installations by merely clicking a button. The primary advantage for adversaries lies in the ability to install applications that run under legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, along with a built-in update mechanism that allows for stealthy modification of installed malware. This sophisticated abuse enables persistence through mechanisms like placing `.appref-ms` files in Startup folders or creating scheduled tasks, providing a robust method for maintaining remote access and evolving malicious payloads without further user interaction or elevated permissions.

## Attack Chain

1.  **Initial Access**: Threat actor sends a phishing email or crafts a malicious website hosting a link to a ClickOnce application to entice victims.
2.  **User Execution**: The victim clicks the malicious link, initiating the ClickOnce application deployment, often deceived by legitimate-looking user interfaces or a lack of awareness about ClickOnce installation.
3.  **Application Installation**: The ClickOnce client (e.g., `dfsvc.exe`) downloads and installs the application components to the user's profile, successfully bypassing typical administrator privilege requirements.
4.  **Malware Execution**: The malicious payload embedded within the ClickOnce application executes, frequently operating under legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, increasing stealth and evading detection.
5.  **Persistence (Shortcut)**: The attacker configures the ClickOnce application for offline availability, leading to the creation of an `.appref-ms` shortcut file in the user's Start Menu, or directly places it into a Startup folder.
6.  **Persistence (Scheduled Task)**: Alternatively, the attacker creates a scheduled task (`schtasks.exe`) to automatically execute the `.appref-ms` file, ensuring the malware restarts upon logon or at predefined intervals.
7.  **Command and Control (C2) and Updates**: The installed ClickOnce application utilizes its built-in update mechanism to periodically fetch new malicious components or updated command and control configurations from an attacker-controlled server.
8.  **Impact**: Persistent remote access is established to the compromised system, enabling the attacker to deliver further payloads, exfiltrate sensitive data, or conduct additional post-exploitation activities.

## Impact

The impact of successful ClickOnce abuse includes unauthorized malware execution, persistent remote access to victim systems, and potential data exfiltration or further compromise. Because these attacks leverage legitimate Microsoft technologies and often bypass traditional defenses, they can lead to stealthy, long-term compromise of user endpoints. The fact that no administrative privileges are required significantly broadens the attack surface to standard users, increasing the potential number of affected hosts within an enterprise, enabling attackers to maintain a foothold and pivot to more sensitive assets.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious `.appref-ms` file manipulation and scheduled task creation.
*   Enable Sysmon process-creation logging to activate the rule `Detect Scheduled Task Creation Referencing ClickOnce AppRef-ms`.
*   Monitor `file_event` logs for the creation or modification of `.appref-ms` files in user Startup folders, as described in `Detect ClickOnce AppRef-ms Persistence in Startup Folder`.
*   Educate users on the risks associated with unsolicited software installation prompts and the characteristics of legitimate application deployments versus suspicious ClickOnce installations.
*   Implement application whitelisting or strict execution policies to prevent unauthorized ClickOnce applications from running.
