---
title: New Abuse of ClickOnce Technology for Stealthy Persistence and Execution
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting the legitimate Microsoft ClickOnce deployment technology to achieve initial access, establish persistence, and execute malicious payloads discreetly on target systems by leveraging its user-friendly deployment, lack of user awareness, and built-in updating mechanism.
date: "2026-07-07T12:56:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - living-off-the-land
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
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder... they can ensure persistence
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: ClickOnce applications for adversaries lies in the fact that they don’t require elevated privileges to be deployed. ... threat actors can target standard user accounts
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Host Process Spawning Suspicious Child
    description: Detects dfsvc.exe or rundll32.exe (legitimate ClickOnce host processes) spawning known suspicious binaries or processes from user-writable locations, indicating potential ClickOnce abuse.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1218.001
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of .appref-ms files within user or system Startup folders, indicating a method of persistence for ClickOnce applications.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce Appref-ms Persistence via Scheduled Task Creation
    description: Detects the creation of scheduled tasks that are configured to execute .appref-ms files, indicating a method of persistence for ClickOnce applications.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

CrowdStrike has identified new abuses of Microsoft's ClickOnce technology, enabling threat actors to deploy malware with minimal user interaction and achieve persistent access. Starting at least as early as 2026, adversaries are exploiting ClickOnce's features, including its ease of deployment, absence of elevated privilege requirements, and built-in update mechanism, to bypass traditional security defenses. This technique capitalizes on a general lack of awareness regarding ClickOnce applications, allowing malicious payloads to execute within legitimate Microsoft process trees (like `rundll32.exe` and `dfsvc.exe`), enhancing stealth. By deploying malicious ClickOnce applications and subsequently pushing updates through attacker-controlled servers, threat actors can maintain remote access and evolve their malware, making this a potent vector for initial compromise and long-term presence on enterprise endpoints.

## Attack Chain

1.  **Initial Access:** Threat actor deceives a user into clicking a malicious link or opening a fraudulent `.application` file, initiating a ClickOnce application deployment.
2.  **Application Deployment:** The user's system downloads and installs the ClickOnce application, often with minimal security prompts, effectively bypassing common email and web filtering systems.
3.  **Legitimate Process Execution:** The ClickOnce application's initial payload executes within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, masking its malicious nature.
4.  **Persistence Mechanism (appref-ms):** A shortcut file (`.appref-ms`) is dropped in the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`), which the attacker can then move or reference for persistence.
5.  **Establishing Persistence:** The threat actor modifies system configurations (e.g., by copying the `.appref-ms` file into a Startup folder or creating a scheduled task) to ensure the malicious ClickOnce application launches automatically.
6.  **Malicious Update Delivery:** The threat actor, maintaining control over the ClickOnce deployment server, pushes a malicious update for the already-installed application.
7.  **Payload Execution via Update:** When the persisted `.appref-ms` file is triggered (via Start Menu, Startup, or Scheduled Task), it automatically fetches the malicious update from the attacker-controlled server and executes the new, malicious payload without further user interaction.
8.  **Impact:** The updated malware establishes persistent remote access, performs data exfiltration, or facilitates further lateral movement within the victim's environment, often undetected due to its legitimate process lineage.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent and stealthy access to targeted systems. Successful exploitation can lead to unapproved software installations, data exfiltration, and lateral movement within the compromised environment. The primary impact stems from the bypass of traditional security controls, low user awareness of ClickOnce's capabilities, and the execution of malicious code under the guise of legitimate Microsoft processes, leading to prolonged dwell times and increased difficulty in detection. This technique affects a wide range of Windows environments where ClickOnce is enabled, impacting various industry sectors through untargeted or spear-phishing campaigns.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related activity.
*   Enable Sysmon `process_creation` and `file_event` logging to activate the rules above effectively.
*   Monitor for the creation or modification of `.appref-ms` files in user-writable or persistence-related directories.
*   Educate users on the risks associated with clicking links or opening files from untrusted sources, particularly those initiating software installations.
