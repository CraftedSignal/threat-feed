---
title: New Abuse of ClickOnce Technology for Stealthy Persistence and Execution
slug: 2026-07-clickonce-abuse
description: Threat actors are actively leveraging Microsoft's ClickOnce technology for initial access, execution, persistence, and defense evasion, bypassing traditional security controls by convincing users to install malicious applications that execute stealthily within legitimate Microsoft process trees and maintain persistence via `.appref-ms` files in startup locations or scheduled tasks.
date: "2026-07-05T11:15:42Z"
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
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - ClickOnce applications
affected_os:
  - Windows
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
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce AppRef-Ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms file in a user's Startup folder, indicating potential persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Schtasks Creation Referencing ClickOnce AppRef-Ms
    description: Detects the use of `schtasks.exe` to create a scheduled task that executes a ClickOnce .appref-ms file, indicating potential persistence.
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

CrowdStrike has highlighted a new abuse of Microsoft's ClickOnce technology, enabling threat actors to achieve initial access, execution, and persistence on Windows endpoints with minimal user interaction. Published on July 5, 2026, this technique exploits the user-friendly nature of ClickOnce deployments, allowing malicious applications to install without elevated privileges and often bypassing traditional security measures like mailbox filters. Attackers convince targets to click a button or `.application` file, triggering a deployment where the malicious payload executes within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. Persistence is achieved by strategically placing `.appref-ms` shortcut files in user Startup folders or creating scheduled tasks, with the built-in ClickOnce update mechanism then leveraged for ongoing command and control (C2) or payload updates. This abuse capitalizes on a general lack of awareness regarding ClickOnce security implications.

## Attack Chain

1.  **Initial Access**: Threat actors conduct social engineering (e.g., via malicious links on webpages or emails) to convince a user to click a button or download and open a malicious `.application` file.
2.  **Execution (Stage 1)**: The user's interaction initiates a ClickOnce application deployment, often requiring minimal authorization due to the technology's design.
3.  **Execution (Stage 2)**: The malicious payload embedded within the ClickOnce application executes, leveraging legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe` to achieve stealth and blend with normal system activity.
4.  **Defense Evasion**: The attack bypasses common security controls (e.g., email filtering, execution policies) due to the use of a legitimate deployment mechanism and low awareness of ClickOnce abuse.
5.  **Persistence**: To maintain access, an `.appref-ms` shortcut file (for offline-available applications) is strategically placed in the user's Startup folder (`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`) or a scheduled task is created to automatically launch the `.appref-ms` file upon login or at regular intervals.
6.  **Command and Control / Updates**: The built-in update mechanism of the ClickOnce application is abused by attackers to push new malicious components, update C2 infrastructure, or modify their payload, often without further user notification.
7.  **Impact**: Sustained remote access, data exfiltration, or the deployment of additional malware is achieved, leading to further compromise of the victim's system and network.

## Impact

The abuse of ClickOnce technology leads to significant impact, primarily enabling stealthy, persistent access to compromised endpoints. Attackers can bypass initial security layers, establish a foothold without requiring administrative privileges, and continuously update their malicious payloads or C2 channels without user knowledge. This can result in long-term unauthorized access, sensitive data exfiltration, deployment of ransomware, or broader network compromise. While no specific victim counts are provided, CrowdStrike observations indicate this method is increasingly used against enterprise endpoints across various sectors due to its effectiveness in evading traditional defenses.

## Recommendation

*   Enable Sysmon file creation and process creation logging to detect suspicious activities related to ClickOnce applications and `.appref-ms` files.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically monitoring for the creation of `.appref-ms` files in startup locations.
*   Implement user education campaigns to raise awareness about the risks of installing untrusted applications, even those appearing legitimate via ClickOnce prompts.
*   Restrict execution of unsigned ClickOnce applications if possible within your environment, though this may impact legitimate business applications.
