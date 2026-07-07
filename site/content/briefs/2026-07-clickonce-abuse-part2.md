---
title: Threat Actors Abusing Microsoft ClickOnce for Persistent Malware Delivery and Command and Control
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively leveraging inherent features of Microsoft's ClickOnce technology to bypass traditional security defenses, deploy malware without elevated privileges, establish persistence through `.appref-ms` files in startup locations or scheduled tasks, and maintain covert command and control via the built-in update mechanism.
date: "2026-07-07T19:40:17Z"
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
  - command-and-control
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
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder... they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded
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
  - title: Suspicious ClickOnce dfsvc.exe Execution
    description: Detects potentially malicious execution of dfsvc.exe (ClickOnce Deployment Support Service) where the parent process is not a typical system service, indicating possible abuse for malware deployment.
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
  - title: ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) within a user's Startup folder, which can indicate an attempt to establish persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Scheduled Task Creation with ClickOnce .appref-ms
    description: Detects the use of 'schtasks.exe' to create a scheduled task that executes a ClickOnce application shortcut (.appref-ms), a common persistence mechanism.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Since June 2026, threat actors have intensified their abuse of Microsoft's ClickOnce deployment technology, a method for quickly deploying Windows applications over the web. This emerging threat leverages ClickOnce's user-friendly deployment, minimal user interaction, and lack of privilege requirements to deliver and persist malware. Adversaries trick users into initiating installations via malicious `.application` files or web buttons, often bypassing traditional email and endpoint defenses. The inherent update mechanism of ClickOnce, facilitated by `.appref-ms` shortcut files, is then weaponized to provide a stealthy and reliable command and control channel, allowing threat actors to update payloads, pivot to lateral movement, or modify C2 infrastructure without further user authorization. Execution often occurs within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, further aiding defense evasion. This novel abuse poses a significant challenge, as it exploits trusted system components to establish long-term presence and control within targeted environments.

## Attack Chain

1.  **Initial Access (User Execution):** A user is lured into clicking a malicious link or opening a fraudulent `.application` file distributed via phishing or untrusted websites.
2.  **Execution (Application Deployment):** The ClickOnce application is deployed, typically triggering execution through legitimate Microsoft processes such as `dfsvc.exe` (ClickOnce Deployment Support Service) or `rundll32.exe`.
3.  **Persistence (Shortcut Creation):** A `.appref-ms` file, a shortcut to the ClickOnce application, is dropped into the user's Start Menu, enabling offline availability.
4.  **Persistence (Autostart/Scheduled Task):** Threat actors strategically place the `.appref-ms` file in the Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or create a scheduled task to automatically launch it.
5.  **Command and Control (Update Check):** Upon launch, the `.appref-ms` file initiates an update check, causing the ClickOnce components to fetch available updates from the attacker-controlled deployment server.
6.  **Ingress Tool Transfer (Malware Update):** The attacker's server delivers a malicious update, replacing the original benign application code with a new, malicious payload without prompting the user for approval.
7.  **Impact (Post-Exploitation):** The updated malicious application gains continued remote access, facilitates lateral movement, exfiltrates data, or performs other attacker-defined objectives, all while operating under the guise of a legitimate application update.

## Impact

The abuse of ClickOnce technology allows threat actors to achieve stealthy initial access and persistent presence within victim networks. This method bypasses common security mechanisms like mailbox filtering and executable scrutiny, as `.application` files are often less policed than `.exe` files. Since ClickOnce applications do not require administrative privileges for deployment, attackers can compromise standard user accounts, broadening their target scope. The built-in update mechanism provides a robust, covert command and control channel, enabling continuous malware updates and adaptation, making detection and eradication challenging. Successful exploitation can lead to prolonged unauthorized access, data exfiltration, further lateral movement, and ultimately, significant operational disruption and financial losses for targeted organizations.

## Recommendation

*   Configure endpoint detection and response (EDR) solutions to monitor and alert on suspicious process parent-child relationships involving `dfsvc.exe` and `rundll32.exe`, especially when their parent is not an expected system service.
*   Deploy the `Suspicious_ClickOnce_dfsvc_Execution` Sigma rule to detect unusual parent processes for `dfsvc.exe`.
*   Deploy the `ClickOnce_Persistence_StartupFolder` Sigma rule to identify `.appref-ms` files being created or modified in Windows Startup directories.
*   Enable comprehensive logging for process creation (Sysmon Event ID 1) and scheduled task creation (Windows Security Event ID 4698) on all Windows endpoints to facilitate detection of ClickOnce abuse.
*   Educate users about the risks of clicking on `.application` files or web buttons that trigger software installations, especially from untrusted sources, to mitigate the T1204.002 (User Execution: Malicious File) initial access vector.
