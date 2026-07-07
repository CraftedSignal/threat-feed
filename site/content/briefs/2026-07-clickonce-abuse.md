---
title: New Abuse of ClickOnce Technology for Stealthy Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology to deploy malware with minimal user interaction, achieve persistence without elevated privileges, and maintain remote access through built-in update mechanisms, enabling stealthy execution within legitimate Microsoft processes.
date: "2026-07-04T07:31:49Z"
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
  - malware-delivery
  - windows
  - microsoft
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
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious ClickOnce Service Host (dfsvc.exe) Activity
    description: Detects potentially malicious execution of the ClickOnce service host (dfsvc.exe) in unusual directories or with suspicious command-line arguments, indicative of ClickOnce abuse for malware delivery.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application Reference (.appref-ms) Persistence
    description: Detects the creation or modification of ClickOnce application reference files (.appref-ms) in user startup locations or suspicious directories, indicating potential persistence mechanisms.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Rundll32.exe Executing ClickOnce Artifacts
    description: Detects instances where rundll32.exe is used to execute ClickOnce related files or functions, which can indicate defense evasion by executing malicious payloads via legitimate system binaries.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are leveraging legitimate features of Microsoft's ClickOnce technology to facilitate stealthy malware delivery and maintain persistent access to target systems. This abuse, highlighted by CrowdStrike, takes advantage of ClickOnce's user-friendly deployment, which requires minimal user interaction and no administrative privileges, allowing malicious applications to bypass traditional security controls like email filtering. By convincing targets to click on malicious links or .application files, adversaries can deploy malware that executes within trusted Microsoft processes like `rundll32.exe` and `dfsvc.exe`. Furthermore, the inherent update mechanism of ClickOnce, managed via `.appref-ms` files, provides a robust method for attackers to update their malware, switch command and control (C2) infrastructure, and move laterally, ensuring long-term access and adaptivity. This campaign is ongoing, with CrowdStrike observing threat actors actively exploiting this lack of awareness around ClickOnce applications.

## Attack Chain

1.  **Initial Access**: Threat actors send malicious links or `.application` files to targets, often via phishing, social engineering, or by embedding deceptive buttons on webpages, enticing users to click.
2.  **Execution**: Upon clicking, the ClickOnce application is deployed and executed on the victim's machine without requiring administrative privileges.
3.  **Deployment & Persistence**: If configured for offline availability, an `.appref-ms` file (application reference) is dropped into the user's Start Menu (%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\), potentially also placed in the Startup folder or via a scheduled task.
4.  **Defense Evasion**: The malicious payload executes under legitimate Microsoft processes, specifically `rundll32.exe` or `dfsvc.exe`, making it difficult for users and security tools to distinguish it from benign system activity.
5.  **C2 Establishment**: The deployed ClickOnce application connects to the attacker-controlled deployment server for updates and command-and-control communications.
6.  **Malware Updates**: Adversaries push malicious updates to the deployment server, which are automatically downloaded and executed by the client application the next time the user launches it via the `.appref-ms` shortcut.
7.  **Impact**: The updated malware enables remote access, lateral movement, data exfiltration, or further compromise of the system without additional user interaction or re-elevation of privileges.

## Impact

The impact of ClickOnce abuse is significant, enabling threat actors to establish covert and persistent footholds within targeted environments. Due to the legitimate nature of ClickOnce, deployed malware can evade traditional security defenses, operate under trusted Microsoft process trees (`rundll32.exe`, `dfsvc.exe`), and update itself stealthily. This allows for long-term remote access, facilitating data exfiltration, lateral movement, or the deployment of additional malicious payloads. The absence of a requirement for administrative privileges lowers the barrier for attackers, making standard user accounts vulnerable to sophisticated and evolving threats that can maintain presence and adapt over time.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Enable Sysmon process-creation logging to detect unusual parent-child relationships involving `rundll32.exe` and `dfsvc.exe`.
*   Monitor for the creation and modification of `.appref-ms` files, especially in unusual directories or by unexpected processes, using file event logging.
*   Educate users about the risks of clicking on unexpected links or downloading `.application` files, even if they appear to originate from trusted sources.
