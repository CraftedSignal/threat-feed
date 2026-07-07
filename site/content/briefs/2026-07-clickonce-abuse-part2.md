---
title: New Abuse of ClickOnce Technology for Initial Access, Execution, and Persistence
slug: 2026-07-clickonce-abuse-part2
description: CrowdStrike reports on threat actors leveraging Microsoft's ClickOnce technology to achieve initial access, execution, and persistence on Windows systems by exploiting its user-friendly deployment and update mechanisms, allowing stealthy malware delivery and execution within legitimate Microsoft processes without requiring elevated privileges.
date: "2026-07-05T06:58:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - execution
  - initial-access
  - defense-evasion
  - malware
  - adversary-in-the-middle
  - endpoint
vendors:
  - Microsoft
products:
  - .NET Framework
  - ClickOnce
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe).
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
iocs:
  - type: file_name
    value: '*.application'
  - type: file_name
    value: '*.appref-ms'
  - type: process_name
    value: rundll32.exe
  - type: process_name
    value: dfsvc.exe
ioc_counts:
  file_name: 2
  process_name: 2
rules:
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of .appref-ms files in a user's Startup folder, which threat actors abuse for persistence using ClickOnce technology.
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
rules_count: 1
---

CrowdStrike has identified a new abuse vector leveraging Microsoft's ClickOnce technology, detailed in their June 2026 report. Threat actors are exploiting its user-friendly deployment and update mechanisms to achieve initial access, execution, and persistence on Windows systems. This technique allows malware delivery without administrative privileges, often bypassing traditional defenses that focus on `.exe` files. Attackers trick users into installing `.application` files, then use `.appref-ms` shortcuts for stealthy persistence and to deliver malicious updates through controlled deployment servers. The malicious payloads execute within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, making detection challenging for unaware organizations. This abuse simplifies the delivery phase of the kill chain and exploits a general lack of awareness regarding ClickOnce security implications.

## Attack Chain

1.  **Initial Access**: Threat actors craft a malicious ClickOnce application, containing their payload, and host it on a controlled web server.
2.  **User Interaction**: The attacker convinces a target user (e.g., via a phishing email containing a link or a deceptive website) to click a button or link that initiates the download and deployment of the malicious `.application` file.
3.  **Deployment & Execution**: The ClickOnce application is deployed with minimal user interaction, downloading and executing the malicious payload on the target system without requiring administrative privileges.
4.  **Stealthy Execution**: The malicious payload executes within legitimate Microsoft process trees, such as `rundll32.exe` or `dfsvc.exe`, making it harder to distinguish from benign system activity.
5.  **Persistence**: The attacker establishes persistence by creating or modifying an `.appref-ms` shortcut in the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or by configuring a scheduled task to launch the malicious ClickOnce application upon system startup or at predefined intervals.
6.  **Command and Control (C2) & Update**: If the ClickOnce application is configured for offline availability, the attacker can leverage its built-in update mechanism. By controlling the deployment server, they can push malicious updates to the installed application, changing C2 addresses, delivering new malware, or performing other actions without further user interaction.
7.  **Impact**: The attacker gains persistent remote access to the compromised system, enabling data exfiltration, further lateral movement, or the deployment of additional malware.

## Impact

The abuse of ClickOnce technology leads to significant security implications, primarily due to its ability to bypass traditional security controls and user scrutiny. Observed damage includes stealthy malware execution, as payloads run within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), making detection difficult. The threat allows for persistence through mechanisms like the Startup folder or scheduled tasks, granting attackers long-term access. This technique lowers the barrier for entry by not requiring elevated privileges, making all standard user accounts vulnerable. The built-in update mechanism enables attackers to dynamically change their C2 infrastructure and malware capabilities post-compromise without re-engaging the user. If successful, organizations face potential data breaches, unauthorized system access, and the spread of malware across their networks.

## Recommendation

*   Enable comprehensive logging for file creation and modification events, particularly in user-specific Startup folders (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`), to activate the `Detect ClickOnce Persistence via Startup Folder` Sigma rule.
*   Monitor process creation events for `rundll32.exe` and `dfsvc.exe` that are initiated by unusual parent processes or lack expected command-line arguments, which could indicate malicious ClickOnce execution.
*   Educate end-users about the risks associated with clicking links from untrusted sources and opening `.application` or `.appref-ms` files, even those appearing to be legitimate software.
*   Implement application whitelisting or strict controls on the execution of `.application` and `.appref-ms` files, especially if they originate from unapproved sources.
*   Deploy the `Detect ClickOnce Persistence via Startup Folder` Sigma rule to your SIEM and tune it for your environment to identify suspicious `.appref-ms` file creations.
