---
title: Threat Actors Abuse ClickOnce for Stealthy Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to facilitate malware delivery, execution, and persistence with minimal user interaction, bypassing security defenses by leveraging its user-friendly deployment, lack of scrutiny, and built-in updating mechanism, executing payloads within legitimate Microsoft processes (like rundll32.exe and dfsvc.exe), and maintaining remote access by pushing malicious updates, with new abuses highlighted using .appref-ms files for stealthy delivery via updates and establishing persistence through placement in the Startup folder or via scheduled tasks.
date: "2026-07-05T07:42:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - defense-evasion
  - initial-access
  - execution
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder...
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: '...or creating a scheduled task.'
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses...
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: '...move laterally, or take other actions.'
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect .appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of .appref-ms files in a user's Startup folder, which is a common persistence mechanism for ClickOnce malware.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation Referencing .appref-ms
    description: Identifies the creation of new scheduled tasks that are configured to execute .appref-ms files, indicating a persistence mechanism leveraging ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application Launch from Suspicious Location
    description: Detects user-initiated execution of ClickOnce .application files from common temporary or download directories, often indicative of initial access via social engineering.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology for stealthy malware delivery and persistence. This abuse leverages ClickOnce's inherent features, such as simplified application deployment with minimal user interaction and automatic updates, to bypass traditional security controls like email filtering and evade scrutiny often applied to executable files. Unlike conventional `.exe` installations, ClickOnce applications can be deployed without elevated privileges, lowering the barrier for attacks against standard user accounts. Adversaries also benefit from the legitimate appearance of ClickOnce processes, which execute payloads within trusted Microsoft binaries like `rundll32.exe` and `dfsvc.exe`, enhancing stealth. A notable abuse involves weaponizing `.appref-ms` files for both stealthy payload updates and establishing persistence via the Windows Startup folder or scheduled tasks, providing a reliable mechanism for remote access and malware updates to facilitate command and control or lateral movement.

## Attack Chain

1.  **Initial Access / Delivery:** Threat actors convince a user to click a malicious link or button, often through social engineering, leading to the download and execution of a ClickOnce `.application` file.
2.  **Execution:** The `.application` file is launched, triggering the ClickOnce deployment process, often mediated by `explorer.exe` or a browser, from a user-writable location like Downloads or Temp.
3.  **Payload Execution:** The malicious payload embedded within the ClickOnce application executes, often within the context of legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, increasing stealth.
4.  **Persistence (Initial Deployment):** An `.appref-ms` shortcut file is dropped in the user's Start Menu (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\`) if the application is configured for offline availability.
5.  **Persistence (Scheduled Task / Startup Folder):** The attacker places the `.appref-ms` file in the Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to automatically launch the malicious ClickOnce application.
6.  **Command and Control / Updates:** Leveraging ClickOnce's built-in update mechanism, the attacker pushes malicious updates from a controlled server, allowing them to change C2 addresses, introduce new functionality, or update malware.
7.  **Impact:** The updated malware gains persistent access, enabling capabilities such as data exfiltration, lateral movement within the network, or further system compromise.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common security protections and establish persistent access within targeted environments. By tricking users into deploying seemingly legitimate applications, attackers can execute arbitrary code within trusted Microsoft processes, effectively hiding their malicious activities. This enables them to maintain remote access, update their malware (e.g., change C2 channels), move laterally across networks, and ultimately achieve objectives such as data exfiltration or deploying further destructive payloads like ransomware. The stealthy nature and minimal user interaction required make detection challenging, leading to prolonged compromise if not actively monitored.

## Recommendation

*   Configure endpoint detection and response (EDR) systems to monitor for the creation of `.appref-ms` files within critical system directories like user Startup folders, as detected by the `Detect .appref-ms Persistence in Startup Folder` rule.
*   Implement robust logging for scheduled task creation and modification events, and deploy the `Detect Scheduled Task Creation Referencing .appref-ms` rule to identify persistence attempts.
*   Enhance process creation logging to capture parent-child relationships and command-line arguments, specifically tuning for `explorer.exe` launching `.application` files from suspicious paths, as identified by the `Detect ClickOnce Application Launch from Suspicious Location` rule.
*   Educate users on the risks associated with installing software from untrusted sources, even when prompted by seemingly legitimate system dialogues, and the behavior of ClickOnce applications.
