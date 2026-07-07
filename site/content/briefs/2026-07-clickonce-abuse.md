---
title: New Abuse of ClickOnce Technology for Initial Access, Persistence, and Evasion
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology for initial access, execution, and persistence by exploiting its user-friendly, low-privilege installation process and general lack of user awareness, enabling them to push malicious updates stealthily and execute payloads within legitimate Microsoft processes for defense evasion.
date: "2026-07-05T06:50:33Z"
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
  - social-engineering
vendors:
  - Microsoft
products:
  - Microsoft ClickOnce
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
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
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
---

CrowdStrike recently detailed how threat actors are increasingly weaponizing Microsoft's ClickOnce technology for initial access, persistence, and defense evasion. This abuse leverages ClickOnce's user-friendly, low-privilege installation process, often bypassing traditional security controls due to a general lack of awareness around `.application` files. Attackers trick users into clicking malicious links or `.application` files, initiating silent software installations. A critical aspect of this technique is the built-in update mechanism, which allows adversaries to deploy malicious updates without further user prompting, thereby maintaining remote access and evolving their malware. Malicious payloads execute under legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, further aiding stealth and evasion. This method creates a powerful attack vector that requires active monitoring, as it lowers the barrier to entry by not requiring elevated privileges and leverages trusted system components.

## Attack Chain

1.  **Initial Access via Social Engineering**: Threat actors craft phishing emails or host malicious websites designed to convince targets to click a link or download a `.application` file.
2.  **ClickOnce Application Deployment**: Upon user interaction (clicking the link or `.application` file), the ClickOnce application is deployed, requiring minimal user input and no elevated administrative privileges for installation.
3.  **Malware Execution**: The malicious payload embedded within the ClickOnce application executes, often within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`, to blend in with normal system activity.
4.  **Persistence Establishment**: To maintain access, the adversary places a shortcut (`.appref-ms` file) to the malicious ClickOnce application in the Windows Startup folder (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task that launches the `.appref-ms` file.
5.  **Stealthy Update Mechanism Abuse**: Once persistent, the ClickOnce application's built-in update mechanism is leveraged. Every time the application starts (e.g., from the Startup folder), it checks for updates from an attacker-controlled server.
6.  **Malicious Payload Update and Evolution**: The attacker pushes malicious updates to the deployment server. The next time the victim launches the ClickOnce application, the updated, more potent malware is silently downloaded and executed without further user consent.
7.  **Command and Control (C2)**: The updated malware establishes C2 communication, allowing the threat actor to change C2 addresses, move laterally within the network, exfiltrate data, or deploy further malicious payloads.
8.  **Impact**: The attacker achieves sustained remote access, network compromise, data exfiltration, or deployment of ransomware or other destructive payloads.

## Impact

The abuse of ClickOnce technology can lead to significant organizational damage by bypassing traditional email and endpoint defenses. The low-privilege installation and silent update mechanism enable persistent remote access, allowing threat actors to maintain a foothold, exfiltrate sensitive data, or deploy ransomware across the victim's network. The stealthy nature of execution within legitimate Microsoft processes makes detection challenging, leading to prolonged compromise and potentially widespread impact across all enterprise endpoints where ClickOnce applications can be installed.

## Recommendation

*   Educate users on the risks associated with clicking suspicious links or `.application` files, especially those requesting software installations outside of official channels, as highlighted in the "Initial Access via Social Engineering" stage of the Attack Chain.
*   Monitor process creation events for `rundll32.exe` and `dfsvc.exe` with unusual command-line arguments or parent processes, as highlighted in the "Malware Execution" step of the Attack Chain.
*   Implement application control or whitelisting solutions to restrict the execution of unsigned or untrusted ClickOnce applications, especially those originating from the internet, to prevent "ClickOnce Application Deployment."
*   Configure endpoint detection and response (EDR) systems to alert on the creation or modification of `.appref-ms` files in Windows Startup folders (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or as part of scheduled tasks, as described in the "Persistence Establishment" step of the Attack Chain.
