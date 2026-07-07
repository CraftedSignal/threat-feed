---
title: New Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology for initial access, execution, and persistence, leveraging its user-friendly deployment that requires minimal user interaction and no elevated privileges to deliver malware via misleading links or `.application` files, using legitimate processes (`rundll32.exe`, `dfsvc.exe`) for stealth, and maintaining remote access through the built-in update mechanism or by placing `.appref-ms` files in autostart locations.
date: "2026-07-05T08:45:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - execution
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
  - .application files
  - .appref-ms
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems. Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: users rarely realize that clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first. This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: med
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
---

Threat actors are increasingly abusing Microsoft's ClickOnce technology, a legitimate application deployment solution, for malicious purposes, as detailed in CrowdStrike's Part 2 analysis published in June 2026. This new abuse vector exploits ClickOnce's minimal user interaction and lack of elevated privilege requirements, simplifying the delivery phase of the kill chain and bypassing traditional security controls. Attackers trick users into clicking misleading links or opening `.application` files, initiating silent installation and execution of malware within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. The inherent update mechanism of ClickOnce, along with the ability to place `.appref-ms` shortcut files in user-controlled autostart locations like the Start Menu or via scheduled tasks, provides a robust persistence mechanism, enabling threat actors to maintain remote access, update payloads, and move laterally without further user consent. This stealthy approach capitalizes on a general lack of awareness around ClickOnce apps, making it a powerful attack vector for enterprise environments.

## Attack Chain

1.  **Initial Access**: Threat actors leverage social engineering tactics, such as phishing emails or malicious websites, to deliver links or `.application` files that initiate a ClickOnce deployment.
2.  **User Execution**: A targeted user clicks a malicious link or opens a deceptive `.application` file, triggering the ClickOnce application installation process.
3.  **Payload Execution**: The ClickOnce deployment executes the embedded malicious payload, typically leveraging legitimate Windows processes like `rundll32.exe` and `dfsvc.exe` to run the malware.
4.  **Persistence (Update Mechanism)**: If the ClickOnce application is configured for offline availability, an `.appref-ms` file is dropped into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`). This allows the attacker to push malicious updates to the application upon subsequent launches without user notification.
5.  **Persistence (Autostart Location)**: The attacker strategically places the `.appref-ms` file in a Windows Startup folder or creates a scheduled task to automatically launch the malicious ClickOnce application upon system boot or at predefined intervals.
6.  **Command and Control**: The persistently running malicious ClickOnce application establishes communication with attacker-controlled infrastructure to receive further commands.
7.  **Impact**: The attacker uses the established access to exfiltrate sensitive data, deploy additional malware, facilitate lateral movement within the network, or achieve other objectives.

## Impact

The successful exploitation of ClickOnce technology allows threat actors to establish persistent access and execute arbitrary code on targeted systems with minimal user interaction and no elevated privileges. This bypasses common security mechanisms, enabling malware execution within legitimate Microsoft process trees, which enhances stealth. Victims can suffer from data exfiltration, deployment of secondary malware (such as ransomware or infostealers), and unauthorized lateral movement across their networks. The attack capitalizes on a low user awareness of ClickOnce behavior, increasing the likelihood of successful compromise and making detection challenging for organizations not specifically monitoring this technology.

## Recommendation

*   Enable comprehensive logging for process creation, including command-line arguments and parent-child relationships, focusing on `rundll32.exe` and `dfsvc.exe` activities.
*   Monitor file system events for the creation of `.application` and `.appref-ms` files, particularly in user-writable directories, Start Menu paths (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`), or other unusual locations.
*   Implement application control policies to restrict the execution of unsigned or untrusted ClickOnce applications.
*   Educate users on the risks associated with unsolicited software installation prompts, especially those related to ClickOnce, and advise them to verify the source before proceeding.
*   Regularly audit Windows Startup folders and scheduled tasks for suspicious `.appref-ms` entries that could indicate persistence.
