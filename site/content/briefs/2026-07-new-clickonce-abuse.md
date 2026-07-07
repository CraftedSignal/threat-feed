---
title: Threat Actors Abuse Microsoft ClickOnce for Stealthy Malware Delivery and Persistence
slug: 2026-07-new-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology for malware delivery, execution, and persistence, capitalizing on minimal user interaction, reduced security scrutiny, and built-in update mechanisms to bypass defenses and maintain remote access without requiring administrative privileges.
date: "2026-07-07T15:23:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - defense-evasion
  - malware
  - microsoft
  - clickonce
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
    technique_id: T1204
    technique_name: User Execution
    evidence: requires minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task to process the file regularly
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: whoever controls the server can update the app. ... the malicious payload will be downloaded and run
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Application Execution by rundll32 or dfsvc
    description: Detects suspicious execution of ClickOnce applications from the user's ClickOnce cache by legitimate Microsoft binaries rundll32.exe or dfsvc.exe, a technique used by threat actors for stealthy malware execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference (.appref-ms) file within the user's Windows Startup folder, a common method for adversaries to achieve persistence without requiring admin rights.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creating ClickOnce Persistence
    description: Detects the creation or modification of a scheduled task using schtasks.exe that targets a ClickOnce application reference (.appref-ms) file, indicating an attempt to establish persistence for a ClickOnce application.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are actively leveraging and abusing Microsoft's ClickOnce technology for malware delivery, execution, and persistence. This ongoing campaign capitalizes on ClickOnce's user-friendly deployment process, which requires minimal user interaction and bypasses traditional security scrutiny often applied to executable files. Attackers can deliver malware through deceptive web buttons or `.application` files, executing payloads without administrative privileges within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, thereby increasing stealth and evading detection. The built-in update mechanism of ClickOnce applications is exploited to maintain persistent remote access and update malware, enabling changes to command and control (C2) infrastructure or facilitating lateral movement. Furthermore, adversaries can establish persistence by dropping `.appref-ms` shortcut files into the Windows Start Menu Startup folder or by creating scheduled tasks to launch these files. This attack vector is particularly effective due to a general lack of awareness regarding ClickOnce security implications among users and some security tools, allowing malicious applications to "fly under the radar."

## Attack Chain

1.  **Initial Access via Deceptive Delivery**: Threat actors convince a user to click a malicious link on a webpage or open a `.application` file delivered via email or other social engineering means, leveraging the user-friendly aspect of ClickOnce deployment.
2.  **ClickOnce Application Deployment**: Upon user interaction, the ClickOnce application deployment process initiates, installing the malicious application silently or with minimal prompts, and notably, without requiring administrator privileges.
3.  **Stealthy Execution**: The malicious payload is executed by legitimate Microsoft processes, specifically `rundll32.exe` or `dfsvc.exe`, masking its true nature and allowing it to run within an expected process tree, thus evading traditional security tool scrutiny.
4.  **Persistence via Shortcut File**: To maintain access, an `.appref-ms` file, which references the installed ClickOnce application, is strategically placed in the user's Startup folder (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).
5.  **Persistence via Scheduled Task**: Alternatively or additionally, a scheduled task is created to regularly execute the `.appref-ms` file, ensuring the malicious application runs at specific intervals or system events.
6.  **Malware Update and C2**: The attacker leverages the ClickOnce application's built-in update mechanism to push malicious updates from a controlled deployment server. These updates automatically download and run when the user starts the application, often without additional user prompts.
7.  **Sustained Remote Access and Objectives**: The updated malware maintains persistent remote access, enabling ongoing command and control (C2), data exfiltration, lateral movement, or other objectives, operating under the guise of a legitimate application.

## Impact

Successful exploitation of ClickOnce technology leads to the stealthy installation and execution of malware on target systems, often bypassing traditional security defenses due to its legitimate process execution and low scrutiny of `.application` files. Attackers gain persistent remote access, can update their malicious payloads as needed for evolving command and control or lateral movement, and can operate without requiring administrative privileges, affecting standard user accounts across an enterprise. The lack of user prompts for updates upon subsequent application launches further exacerbates the risk, allowing benign-appearing applications to transform into malicious ones without user consent, potentially leading to data breaches, system compromise, and significant business disruption.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Enable Sysmon process-creation and file-creation logging to capture telemetry relevant to ClickOnce execution and persistence, which is necessary for the provided rules.
*   Review and enforce application whitelisting policies to prevent the execution of untrusted `.application` files and their subsequent processes.
*   Educate users on the risks associated with unsolicited ClickOnce application deployments and the potential for malicious web buttons or `.application` files.
