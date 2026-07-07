---
title: New Abuse of ClickOnce Technology for Stealthy Malware Deployment and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are abusing Microsoft's ClickOnce technology to deploy malware without elevated privileges, bypassing traditional security defenses by leveraging legitimate deployment processes, built-in update mechanisms of .appref-ms files for persistence and stealthy execution within legitimate Microsoft processes.
date: "2026-07-06T05:03:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - initial-access
  - windows
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
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology to facilitate malware deployment and persistence, circumventing common security controls and requiring minimal user interaction. This abuse, highlighted by CrowdStrike, takes advantage of the technology's user-friendly deployment of `.application` files, which often fly under the radar of security tools designed to scrutinize `.exe` files. A key aspect of this attack involves the `.appref-ms` shortcut, which, when configured for offline access, allows for automated application updates without additional user prompts. This enables attackers to push malicious updates to an initially benign application. Furthermore, the malware executes stealthily within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, making detection challenging. The lack of awareness around ClickOnce applications among users and security teams, combined with the fact that these deployments do not require administrator privileges, makes this a potent attack vector for compromise and sustained presence on targeted Windows systems.

## Attack Chain

1.  **Initial Access (Social Engineering)**: A threat actor entices a user, often through phishing campaigns or deceptive websites, to click a malicious link or open a crafted `.application` file.
2.  **Application Deployment (ClickOnce)**: The user's interaction initiates the ClickOnce deployment process, installing a seemingly benign application onto the system without requiring elevated administrative privileges.
3.  **Persistence Establishment (.appref-ms)**: If the deployed application is configured for offline availability, a `.appref-ms` shortcut file is dropped into the user's Start Menu folder (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) to facilitate subsequent application launches and updates.
4.  **Automated Execution (Persistence)**: To ensure persistence, the threat actor places the `.appref-ms` file in the Startup folder or creates a scheduled task that automatically executes the shortcut upon system boot or at predefined intervals.
5.  **Malicious Update Delivery**: The threat actor, controlling the deployment server, pushes a malicious update for the application. The next time the `.appref-ms` shortcut is launched, it fetches and executes this malicious payload without further user interaction or authorization prompts.
6.  **Execution and Defense Evasion**: The malicious payload executes within legitimate Microsoft processes, such as `rundll32.exe` and `dfsvc.exe`, blending in with normal system activity and making it difficult for traditional security tools to distinguish it from benign operations.
7.  **Command and Control / Impact**: The executed malware establishes command and control (C2), exfiltrates sensitive data, or performs lateral movement, utilizing the built-in update mechanism to maintain persistent access and adapt its malicious capabilities.

## Impact

Successful exploitation of ClickOnce technology allows threat actors to establish persistent access and execute malware on enterprise endpoints, even for standard user accounts without administrative privileges. This can lead to data exfiltration, lateral movement within the network, and the deployment of additional malicious payloads via the inherent update mechanism of ClickOnce applications. The stealthy execution within legitimate Microsoft processes enables these activities to bypass traditional endpoint security controls that focus on scrutinizing known malicious executables. The lack of user awareness regarding ClickOnce's deployment model also contributes to high success rates for initial access, making it a critical threat for organizations.

## Recommendation

*   Enable comprehensive `process_creation` logging (e.g., via Sysmon) to monitor for suspicious command-line executions of `rundll32.exe` and `dfsvc.exe`, especially those originating from unusual parent processes or user-writable locations.
*   Monitor `file_event` logging for the creation or modification of `.appref-ms` files, particularly in user `Startup` folders (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or as part of new `scheduled_tasks`.
*   Implement application whitelisting or strong application control policies to restrict the execution of unsigned or untrusted ClickOnce applications, especially those originating from untrusted web sources.
*   Educate users on the risks associated with installing applications from untrusted sources, even if they appear to be legitimate Microsoft deployments.
