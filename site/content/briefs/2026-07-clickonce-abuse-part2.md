---
title: New Abuse of ClickOnce Technology for Persistent Malware Delivery
slug: 2026-07-clickonce-abuse-part2
description: CrowdStrike identifies new abuse of Microsoft's ClickOnce technology by threat actors leveraging its legitimate features for initial access, stealthy execution within trusted processes, and persistent malware delivery through built-in update mechanisms on Windows systems.
date: "2026-07-07T06:47:41Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - clickonce
  - persistence
  - execution
  - malware-delivery
  - microsoft
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The user-friendliness aspect of the deployment process, which requires minimal user interaction. To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed...Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries...For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries...For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism...every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference file (.appref-ms) within common Windows Startup directories, indicating a potential persistence mechanism. Threat actors abuse the legitimate ClickOnce update mechanism by placing these files in Startup folders to achieve persistent execution.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Executing ClickOnce appref-ms
    description: Detects the creation of scheduled tasks that are configured to execute ClickOnce application reference files (.appref-ms), a technique used by threat actors for persistence and to trigger the built-in update mechanism for ongoing compromise.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike observes new abuse of Microsoft's ClickOnce deployment technology, where threat actors weaponize its features to achieve initial access, execution, and persistence on victim systems. This attack vector leverages ClickOnce's user-friendly deployment, which requires minimal user interaction and often bypasses traditional security mechanisms like email filters, enabling malware delivery through seemingly benign web clicks or `.application` files. Attackers benefit from the general lack of user awareness regarding ClickOnce installations, allowing them to install applications without elevated privileges. The inherent update mechanism of ClickOnce applications is exploited for maintaining remote access and updating malware, changing Command and Control (C2) infrastructure, or facilitating lateral movement. Malicious payloads execute stealthily within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, further obscuring detection. This approach, actively exploited as observed since June 2026, presents a significant challenge as it exploits a trusted Windows feature for long-term compromise.

## Attack Chain

1.  **User Execution**: The threat actor entices a user, often through phishing, to click a malicious link or open a seemingly benign `.application` file distributed via email or untrusted websites.
2.  **Initial ClickOnce Deployment**: The user's interaction initiates the ClickOnce application deployment, downloading the application manifest and associated files from an attacker-controlled server.
3.  **Malicious Payload Execution**: The ClickOnce application, now containing a malicious payload, executes on the victim's system. This execution often occurs stealthily within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`, masking the malicious activity.
4.  **Persistence Establishment (Shortcut Creation)**: If the ClickOnce application is configured for offline availability, an application reference file (`.appref-ms`) is dropped into the user's Start Menu folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\`).
5.  **Automated Execution/Persistence (Startup/Scheduled Task)**: The attacker leverages the `.appref-ms` file for automated persistence, either by directly placing it into a user's Startup folder or by creating a scheduled task that regularly triggers the execution of the `.appref-ms` file.
6.  **Remote Access & Dynamic Updates**: The built-in ClickOnce updating mechanism is exploited. When the `.appref-ms` file is launched (e.g., via Startup or Scheduled Task), it contacts the attacker's deployment server to fetch updates, allowing the threat actor to push new malicious payloads, update malware, change C2 addresses, or facilitate lateral movement.
7.  **Impact**: The victim system is continuously compromised, enabling data exfiltration, further malware deployment, or maintaining long-term remote access without requiring further user interaction.

## Impact

The abuse of ClickOnce technology for malware delivery and persistence leads to significant organizational impact by bypassing conventional security controls and enabling long-term compromise. If successful, threat actors gain stealthy initial access and persistent remote control over targeted systems, which can be continuously updated with new malicious capabilities. This allows for sustained data exfiltration, deployment of additional malware (e.g., ransomware, infostealers), lateral movement within the network, and the establishment of robust Command and Control (C2) channels. The method’s effectiveness lies in exploiting a trusted Windows feature, leading to a higher likelihood of successful compromise and making detection challenging for defenders.

## Recommendation

*   Enable comprehensive logging for file creation events, especially in user profile directories, to detect the creation of `.appref-ms` files in suspicious locations using the `Detect ClickOnce appref-ms Persistence in Startup Folder` rule.
*   Monitor process creation events for `schtasks.exe` to identify the creation of suspicious scheduled tasks that execute `.appref-ms` files, leveraging the `Detect Scheduled Task Executing ClickOnce appref-ms` rule.
*   Implement strong application whitelisting policies to restrict the execution of unsigned or untrusted ClickOnce applications, limiting the initial infection vector.
*   Educate users about the risks associated with unexpected software installations and the characteristics of legitimate ClickOnce prompts versus malicious ones, complementing technical controls.
