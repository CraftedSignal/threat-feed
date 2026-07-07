---
title: New Abuse of ClickOnce Technology for Persistence and Malware Delivery
slug: 2026-07-clickonce-abuse-part2
description: CrowdStrike details how threat actors can exploit Microsoft's ClickOnce technology, leveraging its user-friendly deployment, update mechanism, and execution within legitimate processes to achieve stealthy initial access, persistence via `.appref-ms` files, and covert malware updates without requiring administrative privileges, enabling long-term remote access and control.
date: "2026-07-07T13:52:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - social-engineering
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce Deployment Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
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
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms File Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms shortcut file within a user's Startup folder, indicating potential persistence by threat actors leveraging ClickOnce technology.
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
  - title: Detect Scheduled Task Creation Referencing ClickOnce .appref-ms Files
    description: Detects the use of `schtasks.exe` to create a scheduled task that executes a ClickOnce .appref-ms file, a common persistence mechanism leveraged by threat actors.
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

CrowdStrike has published an analysis detailing new methods by which threat actors can weaponize Microsoft's ClickOnce technology for malicious purposes, building on prior research. This "new abuse" focuses on the inherent features of ClickOnce that simplify application deployment, allowing attackers to bypass traditional security scrutiny on executable files and install malware with minimal user interaction and no administrative privileges. The report highlights how attackers can establish persistence using `.appref-ms` shortcut files, particularly by placing them in the Startup folder or configuring scheduled tasks. Furthermore, the built-in update mechanism of ClickOnce applications allows adversaries to deliver initial benign applications and later push malicious updates covertly. Execution within legitimate `rundll32.exe` or `dfsvc.exe` processes provides an additional layer of stealth, making detection challenging for defenders. This intelligence, published on June 18, 2026, is crucial for organizations relying on Windows environments, as it outlines a potent vector for persistent and stealthy attacks.

## Attack Chain

1.  Threat actor crafts a malicious ClickOnce deployment package, often disguised as a legitimate application, and hosts it on an attacker-controlled server.
2.  Victim receives a social engineering lure (e.g., phishing email or malicious download link) prompting them to install the seemingly benign ClickOnce application.
3.  The victim clicks the provided link or executes a `.application` file, initiating the ClickOnce deployment process without requiring administrative privileges.
4.  The initial ClickOnce application (which could be a benign first stage or a seemingly harmless utility) is installed, and a `.appref-ms` shortcut file is created in the user's Start Menu.
5.  To establish persistence, the threat actor places the `.appref-ms` file into the user's Startup folder (e.g., `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to launch the `.appref-ms` file periodically.
6.  The threat actor then covertly updates the deployment server with a malicious payload, transforming the initial benign application into a fully compromised one.
7.  Upon subsequent execution of the application via the `.appref-ms` file (either manually by the user or automatically by the persistence mechanism), the malicious update is silently fetched and executed by legitimate processes like `rundll32.exe` or `dfsvc.exe`.
8.  The malicious payload establishes command and control (C2), enabling the attacker to maintain remote access, exfiltrate data, or perform further malicious activities on the compromised system.

## Impact

Successful exploitation of ClickOnce technology allows threat actors to bypass common security controls that scrutinize executable files and require administrative privileges for installation. This method enables malware to achieve execution and persistence stealthily, often within legitimate Microsoft process trees, making it difficult to detect. Organizations whose users are susceptible to social engineering or frequently install applications via ClickOnce are at high risk. The attacker gains persistent remote access, enabling data exfiltration, lateral movement, and the potential for a full system compromise, leading to significant financial loss, operational disruption, and reputational damage. The ability to update malware through the built-in ClickOnce mechanism also ensures long-term access and adaptability for the attacker.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable comprehensive file creation/modification logging for `.appref-ms` files, particularly in user Startup directories, to activate the rules above.
*   Monitor scheduled task creation for commands that reference `.appref-ms` files to detect persistence attempts using `schtasks.exe` as detailed in the brief's rules.
*   Educate users on the risks associated with installing applications from untrusted sources, even those presented through user-friendly interfaces like ClickOnce.
*   Implement application whitelisting policies to restrict the execution of unauthorized applications, including those deployed via ClickOnce, from non-approved sources.
