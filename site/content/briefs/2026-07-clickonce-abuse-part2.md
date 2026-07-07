---
title: New Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are weaponizing Microsoft's ClickOnce technology to achieve initial access, execution, and persistence by convincing users to install malicious applications that leverage built-in update mechanisms and execute within legitimate process trees without requiring elevated privileges.
date: "2026-07-06T09:52:46Z"
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
  - microsoft
  - windows
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
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
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence in Startup Folder
    description: Detects the creation of .appref-ms files in the Windows Startup folder, a known technique for ClickOnce persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce Appref-ms Persistence via Scheduled Task
    description: Detects the creation of scheduled tasks designed to execute ClickOnce .appref-ms files, indicating persistence.
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

CrowdStrike has identified new abuses of Microsoft's ClickOnce technology, enabling threat actors to bypass traditional security defenses and establish persistent access. Commencing before July 2026, attackers are leveraging ClickOnce's user-friendly deployment, which requires minimal interaction and no elevated privileges, to distribute malware. They exploit a general lack of awareness about `.application` files compared to `.exe` files, making it easier to trick users into installing malicious software. A key innovation in this abuse is using ClickOnce's built-in update mechanism to maintain remote access, update malware, and facilitate lateral movement. Malicious payloads execute within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, further aiding evasion. This technique presents a significant challenge as it leverages trusted platform features for nefarious purposes.

## Attack Chain

1.  **Initial Access**: Threat actors craft malicious ClickOnce application links or prepare `.application` files.
2.  **User Interaction**: Victims are lured via social engineering (e.g., phishing emails, malicious websites) to click the provided link or open the `.application` file.
3.  **Application Deployment**: Windows initiates the ClickOnce deployment process, presenting a legitimate Microsoft UI for installation and requiring minimal user input, often without administrative privileges.
4.  **Payload Execution**: The deployed malicious ClickOnce application executes its payload within legitimate Microsoft processes, such as `rundll32.exe` or `dfsvc.exe`, making it stealthier.
5.  **Persistence Establishment**: The attacker establishes persistence by dropping a malicious `.appref-ms` shortcut file into the Windows Startup folder (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or by creating a Scheduled Task to launch the `.appref-ms` file.
6.  **Malware Update and Command & Control**: The attacker leverages ClickOnce's built-in update mechanism to push updates to the deployed application, enabling ongoing command and control (C2), lateral movement, or the delivery of additional malicious modules upon subsequent application launches.
7.  **Impact**: The malicious application performs its ultimate objective, which can include data exfiltration, further system compromise, or the deployment of ransomware.

## Impact

The abuse of ClickOnce technology allows threat actors to successfully deploy malware, maintain persistent access, and evade detection by executing within legitimate Microsoft processes. Organizations may experience data breaches, system compromise, or the installation of various types of malicious software without the need for administrative privileges, affecting a wide range of endpoints. The technique exploits common user behavior and a lack of awareness, leading to potentially widespread infections and significant operational disruption if not effectively detected and mitigated.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related persistence and execution.
*   Enable Sysmon `EventID 1 (Process Create)` and `EventID 11 (FileCreate)` logging to capture relevant events for the rules provided.
*   Educate users on the risks associated with clicking suspicious links or opening `.application` files, even if they appear to originate from trusted sources.
*   Monitor for the creation or modification of `.appref-ms` files in persistence locations, such as the Startup folder or via scheduled tasks, as described in the `Detect ClickOnce Appref-ms Persistence in Startup Folder` rule.
*   Monitor `schtasks.exe` process creation events for suspicious parameters that indicate the creation of new scheduled tasks launching `.appref-ms` files, as covered by the `Detect ClickOnce Appref-ms Persistence via Scheduled Task` rule.
