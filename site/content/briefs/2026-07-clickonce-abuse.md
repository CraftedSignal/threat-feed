---
title: Threat Actors Actively Abusing Microsoft ClickOnce for Initial Access, Execution, and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are leveraging Microsoft's ClickOnce deployment technology, particularly its update and persistence mechanisms, to bypass traditional defenses, achieve initial access without elevated privileges, and maintain remote access on target Windows systems by deploying and updating malicious applications.
date: "2026-07-07T15:35:16Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - execution
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
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
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
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect dfsvc.exe Launching Suspicious Child Processes
    description: Detects instances where the legitimate Microsoft ClickOnce Deployment Support Service (dfsvc.exe) launches known malicious or scripting binaries, indicating potential abuse or compromise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.004
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce .appref-ms File Creation in Startup Folder
    description: Detects the creation or modification of ClickOnce application reference files (.appref-ms) within a user's Startup folder, which is a known technique for achieving persistence without requiring administrative privileges.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology for malicious purposes, as detailed in a recent CrowdStrike analysis. This abuse, observed since at least Black Hat USA 2019 and evolving with new methods, allows adversaries to achieve initial access and maintain persistence with minimal user interaction and without requiring administrative privileges. The inherent user-friendliness of ClickOnce, coupled with a general lack of awareness among users and security tools regarding `.application` files, enables attackers to deliver payloads stealthily. Malicious applications are deployed and updated through ClickOnce's built-in mechanisms, running within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`. This method provides a reliable vector for remote access, C2 updates, and lateral movement, posing a significant challenge to traditional endpoint security.

## Attack Chain

1.  **Initial Access / Delivery**: Threat actors deliver a malicious ClickOnce application either by convincing a user to click a misleading button on a webpage or by distributing `.application` files, often bypassing email filters.
2.  **User Execution**: The user clicks the link or `.application` file, triggering the ClickOnce deployment process, which requires minimal user input.
3.  **Malicious Application Deployment**: The ClickOnce application installs and the embedded malicious payload executes within legitimate Microsoft process trees, specifically involving `rundll32.exe` and `dfsvc.exe`.
4.  **Persistence Mechanism Deployment**: If configured for offline availability, an application reference file (`.appref-ms`) is dropped into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Persistence via Startup Folder**: Adversaries place the `.appref-ms` file into the Windows Startup folder (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or create a scheduled task to process it regularly, ensuring execution upon system boot or at intervals.
6.  **Stealthy Payload Update**: The attacker pushes malicious updates to the deployment server controlling the ClickOnce application.
7.  **Malicious Update Execution**: The next time the user starts the application via the `.appref-ms` shortcut (either manually or via the persistence mechanism), the ClickOnce components fetch and execute the updated malicious payload without further user prompts.
8.  **Impact / Command and Control**: The updated payload grants the attacker remote access, facilitates C2 communication changes, enables lateral movement, or performs data exfiltration.

## Impact

The impact of ClickOnce abuse includes the stealthy deployment of malware, bypassing traditional defenses that scrutinize `.exe` files. Since these attacks do not require administrative privileges, standard user accounts, which comprise the majority of enterprise endpoints, are vulnerable. Once established, adversaries can maintain remote access and update their malicious tools via the built-in ClickOnce update mechanism, enabling persistent C2, lateral movement, and data exfiltration. The execution within legitimate Microsoft processes further increases stealth, making detection challenging and allowing attackers to remain undetected for longer periods.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related activity.
*   Enable Sysmon process-creation logging to capture parent-child process relationships for `dfsvc.exe` and `rundll32.exe`.
*   Enable Sysmon file-creation logging to monitor the creation of `.appref-ms` files, especially in Startup folders.
*   Educate users about the risks associated with clicking links or downloading files from untrusted sources, particularly `.application` files, as these can trigger software installations without clear warnings.
