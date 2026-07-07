---
title: Threat Actors Actively Abusing Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology to gain initial access, achieve persistence, and perform defense evasion, leveraging its user-friendly deployment and built-in update mechanisms to deliver and update malicious payloads on enterprise endpoints without requiring elevated privileges.
date: "2026-07-06T08:53:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - windows
  - defense-evasion
  - user-execution
vendors:
  - Microsoft
products:
  - Microsoft Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
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
    evidence: placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task
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
    evidence: threat actors benefit from a built-in updating mechanism... whoever controls the server can update the app.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder or Run Key
    description: Detects the creation of ClickOnce application reference files (.appref-ms) in the Windows Startup folder or modifications to Run registry keys to achieve persistence, a common tactic in ClickOnce abuse.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task Creation
    description: Detects the creation of scheduled tasks that are configured to execute ClickOnce application reference files (.appref-ms), a technique used by threat actors for persistence.
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

Threat actors are increasingly weaponizing Microsoft's ClickOnce technology to bypass traditional security defenses and establish persistent access on target systems. This new abuse, highlighted by CrowdStrike on June 18, 2026, capitalizes on the minimal user interaction required for ClickOnce application deployment and a general lack of awareness regarding `.application` files. Attackers can deliver malware without necessitating elevated privileges, as ClickOnce apps run in user context. A key aspect of this abuse involves using ClickOnce's built-in updating mechanism to maintain remote access and dynamically update their malware, allowing for changes in command and control (C2) addresses, lateral movement, or other malicious actions. Malicious payloads execute stealthily within legitimate Microsoft process trees, including `rundll32.exe` and `dfsvc.exe`, further aiding evasion. Persistence can be achieved by placing `.appref-ms` files in the Startup folder or creating scheduled tasks that trigger application execution.

## Attack Chain

1.  **Initial Access:** Threat actors leverage social engineering (e.g., misleading buttons on webpages, phishing emails) to convince users to click a link or open an `.application` file, initiating a ClickOnce application deployment.
2.  **Execution (Initial):** Upon user interaction, the malicious ClickOnce application is downloaded and executed. This process typically involves `dfsvc.exe` (Client Application Services) and `rundll32.exe`, running the initial payload within legitimate Microsoft process trees.
3.  **Persistence (Shortcut):** The attacker configures the malicious ClickOnce application for offline availability, causing a shortcut (`.appref-ms` file) to be dropped in the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence (Autostart/Scheduled Task):** To ensure execution upon system restart or at set intervals, the attacker places the `.appref-ms` file in the Windows Startup folder or creates a scheduled task to automatically open the `.appref-ms` file.
5.  **Defense Evasion:** The malicious payload operates under the guise of legitimate ClickOnce processes (`rundll32.exe` and `dfsvc.exe`), displaying authentic Microsoft UI elements, which aids in evading detection by traditional security solutions.
6.  **Command and Control / Updates:** Leveraging ClickOnce's built-in update mechanism, the attacker pushes malicious updates from a controlled deployment server. When the user launches the application via the persisted shortcut, the system fetches and executes the updated malicious payload without further authorization.
7.  **Objective Achievement:** The updated malicious payload gains sustained remote access, facilitates lateral movement, exfiltrates sensitive data, or deploys additional malware, often without requiring elevated user privileges.

## Impact

The abuse of ClickOnce technology leads to successful initial compromises and sustained presence within victim environments. While specific victim numbers are not provided, the technique targets a wide range of enterprise endpoints running Microsoft Windows. The impact includes unauthorized remote access, potential data exfiltration, and the deployment of additional malicious tools or ransomware, all executed with a high degree of stealth and often bypassing traditional security controls due to the perceived legitimacy of the ClickOnce process. The ability for attackers to update their malware through the built-in ClickOnce mechanism allows for dynamic adaptation of C2 infrastructure and capabilities, making long-term compromise more challenging to detect and remediate.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically focusing on `file_event`, `registry_set`, and `process_creation` logs.
*   Enable comprehensive logging for `process_creation`, `file_event`, and `registry_set` on all Windows endpoints to capture activities related to `.appref-ms` files and scheduled tasks.
*   Educate users about the risks associated with clicking suspicious links or opening unsolicited `.application` files, even if they appear to originate from trusted sources.
*   Implement application whitelisting policies to restrict the execution of unauthorized ClickOnce applications or unsigned `.application` files.
