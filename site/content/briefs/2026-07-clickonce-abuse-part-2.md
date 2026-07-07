---
title: Threat Actors Actively Abusing Microsoft ClickOnce for Stealthy Malware Deployment and Persistence
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are exploiting Microsoft's ClickOnce technology to deploy malware with minimal user interaction and no elevated privileges, leveraging `.application` or `.appref-ms` files for initial execution, establishing persistence via Startup folders or scheduled tasks, and utilizing ClickOnce's update mechanism for long-term command and control and defense evasion within legitimate Microsoft processes.
date: "2026-07-07T13:18:09Z"
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
  - malware
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: When configured to be available offline, an application reference file (.appref-ms) is dropped at the installation of the application in the Start Menu... This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence via Startup Folder
    description: Detects the creation of an '.appref-ms' file in a user's Startup folder, a known technique for ClickOnce persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

CrowdStrike has identified a new wave of abuse targeting Microsoft's ClickOnce technology, which threat actors are weaponizing to deliver malware and establish persistent access. The abuse, detailed in a blog post published on June 18, 2026, highlights how adversaries exploit ClickOnce's user-friendly deployment and inherent trust to bypass traditional security mechanisms. Attackers entice users to click on malicious `.application` files or web buttons, leading to the installation of malware without requiring administrative privileges. This method allows payloads to execute within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, significantly increasing stealth. Furthermore, the built-in update mechanism of ClickOnce applications is being leveraged to maintain remote access and update malicious components, enabling long-term compromise and control over affected systems.

## Attack Chain

1.  **Initial Access**: Threat actor entices a user to click on a malicious link pointing to a ClickOnce application hosted on a server, often delivered as a `.application` file or triggered by a misleading button on a webpage.
2.  **Initial Execution**: Upon clicking, the ClickOnce deployment service (`dfsvc.exe`) downloads and attempts to install the application, which is configured to execute a malicious payload.
3.  **Payload Execution**: The ClickOnce application launches its embedded malicious payload, frequently utilizing `rundll32.exe` to execute arbitrary code or scripts, masking the malicious activity under a legitimate Windows binary.
4.  **Persistence (Appref-ms Drop)**: A malicious `.appref-ms` shortcut file, representing the deployed ClickOnce application, is dropped into a user's `%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\` directory.
5.  **Persistence (Startup/Scheduled Task)**: To ensure continued execution, the `.appref-ms` file is strategically placed in the Windows Startup folder or a scheduled task is created to automatically open the `.appref-ms` file upon user logon or at set intervals.
6.  **Defense Evasion**: The malicious code executes within the context of legitimate Microsoft processes (`dfsvc.exe`, `rundll32.exe`), blending in with normal system activity and avoiding detection by security tools focused on flagging unknown or suspicious executables.
7.  **Command and Control / Update**: The threat actor leverages the ClickOnce application's built-in update mechanism to push new malicious components, modify command and control (C2) infrastructure, or deploy additional malware to the compromised system.
8.  **Impact**: The attacker gains remote access, maintains persistence, and can proceed with objectives such as data exfiltration, lateral movement, or deploying ransomware.

## Impact

This ClickOnce abuse provides threat actors with a highly effective method for initial access, persistence, and defense evasion, circumventing security controls that typically scrutinize `.exe` files. Successful exploitation leads to unauthorized remote access to target systems, allowing attackers to maintain a foothold, update their malware without user prompting, and potentially move laterally across networks. While the brief doesn't specify victim counts or particular sectors, the nature of this attack, requiring minimal user interaction and no elevated privileges, indicates a broad potential impact across any organization using Windows systems.

## Recommendation

*   Deploy the provided Sigma rule to detect suspicious `.appref-ms` persistence mechanisms.
*   Enable comprehensive `process_creation` logging and monitor for unusual child processes spawned by `dfsvc.exe` and `rundll32.exe`.
*   Monitor `file_event` logs for the creation of `.application` and `.appref-ms` files in atypical user directories or system locations outside of standard software installations.
*   Enable `scheduled_task` creation logging and monitor for new tasks that execute `.appref-ms` files, which could indicate persistence.
