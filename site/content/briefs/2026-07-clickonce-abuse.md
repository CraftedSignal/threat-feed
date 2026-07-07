---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse
description: Threat actors are leveraging Microsoft's ClickOnce technology, specifically by weaponizing .appref-ms files and the application update mechanism, to achieve initial access, establish persistence, and maintain command and control on targeted Windows systems, often bypassing traditional security controls due to minimal user interaction and execution within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`.
date: "2026-07-07T13:03:12Z"
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
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
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
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious ClickOnce Execution via Rundll32/dfsvc
    description: Detects suspicious execution patterns involving rundll32.exe or dfsvc.exe with command line arguments indicative of ClickOnce application loading, which can be abused by threat actors.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce .appref-ms Persistence
    description: Detects the creation or modification of .appref-ms files in common Windows persistence locations like the Startup folder, indicating potential abuse of ClickOnce for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Threat actors are actively abusing Microsoft's ClickOnce deployment technology, leveraging its user-friendly installation process and lack of traditional security scrutiny to facilitate initial access, establish persistence, and maintain command and control. This "new abuse" was highlighted by CrowdStrike in June 2026, observing that malicious ClickOnce applications can be delivered via seemingly benign web buttons or `.application` files. The technique bypasses common security mechanisms as it does not require elevated privileges and executes payloads within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. Furthermore, the built-in update mechanism allows adversaries to silently transform benign applications into malicious ones, ensuring a persistent foothold and reliable method for updating malware and maintaining remote access. This presents a significant challenge for defenders as it allows for stealthy and persistent compromises.

## Attack Chain

1.  **Initial Access**: Threat actor socially engineers a user to click a malicious web button or open an `.application` file.
2.  **Execution (Initial Deployment)**: The user's interaction triggers the ClickOnce deployment, installing a malicious or initially benign application without requiring administrative privileges.
3.  **Persistence (Shortcut Creation)**: The deployed ClickOnce application drops an `.appref-ms` shortcut file, typically in `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`.
4.  **Execution (Legitimate Process Abuse)**: The malicious payload associated with the ClickOnce application executes within legitimate Microsoft process trees, specifically `rundll32.exe` and `dfsvc.exe`, increasing stealth.
5.  **Persistence (Elevated)**: For enhanced persistence, the threat actor moves the `.appref-ms` file to the Startup folder (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or creates a scheduled task to regularly execute the `.appref-ms` file.
6.  **Command and Control (Update Mechanism)**: The attacker pushes a malicious update to their controlled ClickOnce deployment server.
7.  **Execution (Silent Update)**: The next time the user launches the ClickOnce application via its `.appref-ms` file, the malicious update is silently downloaded and executed without further user authorization, transforming the application into a full-fledged malware.
8.  **Impact**: The updated malicious application maintains remote access, performs data exfiltration, lateral movement, or executes other attacker objectives.

## Impact

This abuse of ClickOnce technology can lead to silent and persistent compromise of Windows systems. While specific victim counts or targeted sectors are not detailed in this report, the observed techniques allow threat actors to bypass traditional endpoint security, gain persistent remote access, and facilitate subsequent malicious activities such as data exfiltration, lateral movement, or ransomware deployment. The execution within legitimate Microsoft processes and the silent update mechanism make these attacks particularly difficult to detect and eradicate, potentially leading to long-term unauthorized access and significant data breaches.

## Recommendation

*   Enable `process_creation` and `file_event` logging (e.g., via Sysmon) to support the detection rules provided in this brief.
*   Deploy the `Detect Suspicious ClickOnce Execution via Rundll32/dfsvc` Sigma rule to your SIEM and tune for your environment.
*   Deploy the `Detect ClickOnce .appref-ms Persistence` Sigma rule to your SIEM and tune for your environment.
