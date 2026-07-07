---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are increasingly exploiting Microsoft's ClickOnce technology, specifically abusing its update mechanism and file shortcuts, to deliver malware and establish persistence on Windows endpoints without requiring administrative privileges, thereby bypassing traditional defenses.
date: "2026-07-04T08:17:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce
  - Windows
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
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)... Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
---

Threat actors are actively leveraging Microsoft's ClickOnce application deployment technology for stealthy malware delivery and persistence. This abuse stems from ClickOnce's user-friendly deployment, which requires minimal user interaction and no administrator privileges, allowing attackers to target standard user accounts. The technique exploits a general lack of awareness around `.application` and `.appref-ms` files, enabling malicious payloads to bypass common email and endpoint security controls that often scrutinize `.exe` files. A significant aspect of this new abuse involves weaponizing the built-in update mechanism: once a user installs a seemingly harmless ClickOnce application, attackers can push malicious updates from their controlled deployment server. Furthermore, the `.appref-ms` shortcut files, normally placed in the Start Menu, can be leveraged for persistence by placing them in Windows Startup folders or using them in scheduled tasks, with the final payload executing within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe` to further evade detection.

## Attack Chain

1.  **Initial Access**: A threat actor conducts social engineering (e.g., via phishing email or malicious website) to lure a victim into clicking a link that directly initiates a ClickOnce application deployment or downloads an `.application` file.
2.  **User Execution**: The victim clicks the malicious link or executes the downloaded `.application` file, triggering the installation of a seemingly benign ClickOnce application.
3.  **Application Installation**: The ClickOnce application is deployed, configured for offline availability, and drops an `.appref-ms` shortcut file in the user's Start Menu (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Malicious Update Staging**: The attacker, who controls the ClickOnce deployment server, updates the deployed application with a malicious payload.
5.  **Malicious Update Execution**: When the victim next launches the installed application via the `.appref-ms` shortcut from the Start Menu, the built-in update mechanism fetches and executes the malicious update without further explicit user prompts.
6.  **Persistence**: The attacker establishes persistence by placing the `.appref-ms` file in the Windows Startup folder or creating a scheduled task to automatically launch the application, ensuring continuous execution of the malicious payload.
7.  **Defense Evasion & Payload Execution**: The malicious payload executes under legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, utilizing legitimate Microsoft UI elements to blend with normal system activity and evade detection.
8.  **Impact**: The attacker gains and maintains remote access, can update their malware, perform lateral movement, exfiltrate data, or deploy further malicious tools.

## Impact

Successful exploitation allows threat actors to gain persistent access to enterprise endpoints, often bypassing traditional security defenses that focus on `.exe` files or require elevated privileges. This technique can lead to the installation of various malware, including infostealers, ransomware, or remote access tools, impacting data confidentiality, integrity, and availability. Since the attack targets standard user accounts and executes within legitimate processes (e.g., `rundll32.exe`, `dfsvc.exe`), it creates a stealthy foothold that can facilitate lateral movement and further compromise critical systems and data, potentially leading to widespread organizational disruption or significant financial losses.

## Recommendation

*   Enable comprehensive logging for process creation and file events, specifically monitoring for the creation and execution of `.application` and `.appref-ms` files, to detect the initial stages of ClickOnce abuse.
*   Monitor for the creation of `.appref-ms` files in unusual or non-standard locations outside of `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\` to identify attempts at persistence.
*   Detect suspicious child processes of web browsers that launch `rundll32.exe` or `dfsvc.exe`, especially when associated with ClickOnce application deployment or updates.
*   Implement application whitelisting and robust reputation checks for applications launched by ClickOnce, even if they appear legitimately signed, as the update mechanism can be weaponized.
*   Deploy endpoint detection and response (EDR) solutions capable of monitoring and analyzing the execution context of `.application` and `.appref-ms` files, and their subsequent process trees involving `rundll32.exe` or `dfsvc.exe`.
