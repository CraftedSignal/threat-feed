---
title: Threat Actors Weaponize Microsoft ClickOnce for Persistent Malware Delivery and Execution
slug: 2026-07-clickonce-abuse-p2
description: Threat actors are abusing Microsoft's ClickOnce technology to facilitate malware delivery and persistence, leveraging its user-friendly deployment and minimal user interaction requirements, allowing malicious payloads to bypass traditional defenses by executing within legitimate Microsoft processes and utilizing built-in update mechanisms for stealthy command and control.
date: "2026-07-04T06:53:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - malware-delivery
  - windows
  - defense-evasion
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice
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
    evidence: or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Persistence via ClickOnce .appref-ms in Startup Folder
    description: Detects the creation of an .appref-ms file in a user's Startup folder, indicating an attempt to establish persistence using abused ClickOnce functionality.
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

Threat actors are increasingly exploiting Microsoft's ClickOnce technology as a sophisticated method for malware delivery and maintaining persistence on compromised systems. This new abuse, highlighted by CrowdStrike, takes advantage of ClickOnce's design which allows applications to be deployed with minimal user interaction, often requiring just one or two clicks. The method enables attackers to bypass traditional security controls like email filters and evade scrutiny, as `.application` files are often less scrutinized than standard executables. A key feature exploited is ClickOnce's built-in update mechanism, which allows attackers to modify deployed malware by pushing new payloads from a controlled server without additional user consent. Furthermore, adversaries achieve stealthy execution by operating within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, making detection challenging for defenders. This technique significantly lowers the bar for entry, as ClickOnce applications do not require elevated privileges for installation, targeting standard user accounts that comprise the majority of enterprise endpoints.

## Attack Chain

1.  **Initial Access**: Threat actors leverage social engineering to trick users into clicking a malicious link or button, often on a webpage, that initiates a ClickOnce application deployment.
2.  **Initial Execution**: The user's click triggers the ClickOnce deployment process, which legitimately invokes Microsoft's `dfsvc.exe` (ClickOnce Deployment Service) and potentially `rundll32.exe` to process the `.application` manifest and execute the initial malicious payload.
3.  **Bypass Defenses**: The `.application` file and subsequent execution often fly under the radar of traditional security tools and user scrutiny due to their perceived legitimacy compared to standard `.exe` files.
4.  **Persistence (Shortcut)**: The attacker configures the ClickOnce application to be available offline. Upon installation, a malicious `.appref-ms` shortcut file is dropped into the user's Start Menu.
5.  **Persistence (Autostart)**: The attacker places the malicious `.appref-ms` file into the Windows Startup folder (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to automatically launch it upon user login or at a specific interval.
6.  **Defense Evasion (Process Hiding)**: Malicious code executes within the context of legitimate Microsoft processes (`dfsvc.exe`, `rundll32.exe`), blending with normal system activity and making it difficult for security solutions to differentiate benign from malicious behavior.
7.  **Command and Control / Payload Update**: By controlling the deployment server, the attacker can push malicious updates to the ClickOnce application at any time, allowing for dynamic changes to command and control (C2) addresses, downloading additional tools (Ingress Tool Transfer), or modifying malware functionality without further user interaction.
8.  **Impact**: The updated malware establishes persistent remote access, facilitates lateral movement, exfiltrates data, or performs other malicious activities leading to further system compromise.

## Impact

The abuse of ClickOnce technology leads to significant security risks, primarily through stealthy malware delivery and persistent access. Victims face the risk of system compromise without immediate detection, as the initial execution and subsequent updates blend into legitimate system processes. This technique bypasses common security mechanisms, making organizations vulnerable to remote access, data exfiltration, and the deployment of additional malicious payloads. While no specific victim count is provided, the described techniques are broadly applicable across Windows environments, targeting any user susceptible to social engineering, regardless of sector.

## Recommendation

*   Enable Sysmon Event ID 11 (FileCreate) logging to detect the creation of suspicious `.appref-ms` files in critical directories, such as the Startup folder, and deploy the "Persistence via ClickOnce .appref-ms in Startup Folder" Sigma rule to your SIEM.
*   Educate end-users about the risks associated with ClickOnce applications, especially those originating from untrusted sources, and train them to identify misleading buttons or prompts.
*   Implement application whitelisting or strict application control policies to prevent the execution of unauthorized ClickOnce applications or limit their privileges, reducing the effectiveness of this attack vector.
*   Monitor network traffic for unusual outbound connections from `dfsvc.exe` or `rundll32.exe` that are not consistent with known legitimate ClickOnce application update patterns.
