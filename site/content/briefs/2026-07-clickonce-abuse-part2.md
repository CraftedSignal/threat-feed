---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are abusing Microsoft's ClickOnce technology on Windows systems to bypass traditional security defenses and establish persistent access by exploiting its user-friendly deployment for malware execution via .application files, leveraging built-in update mechanisms for payload delivery, and maintaining persistence through .appref-ms files in startup folders or scheduled tasks, while blending malicious execution within legitimate Microsoft processes like rundll32.exe and dfsvc.exe.
date: "2026-07-04T08:37:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - defense-evasion
  - initial-access
  - microsoft
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Malicious ClickOnce Execution via rundll32 or dfsvc
    description: Detects suspicious processes launched by rundll32.exe or dfsvc.exe, which are legitimate Microsoft processes known to be abused for ClickOnce malware execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of an .appref-ms file within a user's Startup folder, indicating an attempt to establish persistence for a ClickOnce application.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Threat actors are increasingly weaponizing Microsoft's ClickOnce deployment technology to deliver malware and establish persistence on target systems, as detailed by CrowdStrike in June 2026. This abuse leverages the inherent user-friendliness of ClickOnce applications, which require minimal interaction for installation, enabling attackers to bypass traditional email filtering and user scrutiny of executable files. The primary motivation for this shift is the ease of initial access and persistence; attackers can either compromise legitimate ClickOnce servers to push malicious updates or trick users into installing benign apps that are later backdoored. Malware execution is cloaked within trusted Microsoft processes like `rundll32.exe` and `dfsvc.exe`, significantly complicating detection for security teams and enhancing stealth throughout the attack lifecycle. This trend highlights a critical blind spot in enterprise security, as `.application` files often fly under the radar compared to more heavily scrutinized `.exe` files, making it a powerful and effective vector for sophisticated adversaries.

## Attack Chain

1.  **Initial Access**: Threat actors craft a malicious ClickOnce application and host it on a deployment server. They then trick users into clicking a link on a webpage or opening a `.application` file, which initiates the ClickOnce installation process, often bypassing email filtering and traditional executable scrutiny.
2.  **Execution**: Upon user interaction, the ClickOnce application deploys and executes its payload. The malicious code runs under the guise of legitimate Microsoft processes, specifically within `rundll32.exe` and `dfsvc.exe` process trees.
3.  **Persistence (Offline Shortcut)**: If the ClickOnce application is configured for offline availability, an application reference file (`.appref-ms`) is dropped into the user's Start Menu directory (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence (Startup Folder)**: For automated execution, adversaries can strategically place the `.appref-ms` file in a user's Startup folder, causing the ClickOnce application to launch every time the user logs in.
5.  **Persistence (Scheduled Task)**: Alternatively, attackers can create a scheduled task configured to automatically open the `.appref-ms` file at specific intervals or system events, ensuring regular re-execution of the malicious ClickOnce application.
6.  **Defense Evasion & C2**: The `.appref-ms` file, when opened, triggers the ClickOnce components to fetch updates from the deployment server. If the server is controlled by the attacker or has been compromised, the malicious application can be updated with new components, allowing for C2 communication, lateral movement, or additional malicious activities without further user prompts.
7.  **Impact**: The attacker gains remote access and persistence, enabling further actions such as data exfiltration, installation of additional malware, lateral movement, or system compromise, all while operating under the radar of traditional security tools.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for entry for threat actors, enabling them to target standard user accounts and bypass typical security controls. This can lead to widespread compromise across various sectors, as any organization relying on Microsoft Windows endpoints is potentially vulnerable. If successful, attackers can establish persistent remote access, facilitate data exfiltration, deploy ransomware, or engage in lateral movement within the compromised network. The stealthy nature of this attack, executing within legitimate Microsoft processes, makes it difficult to detect, potentially leading to prolonged dwell times and extensive damage before discovery.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Enable Sysmon process-creation and file-creation logging to capture the artifacts necessary for the `Detect ClickOnce .appref-ms Persistence via Startup Folder` and `Detect Malicious ClickOnce Execution via rundll32 or dfsvc` rules.
*   Monitor for the creation of `.appref-ms` files in unusual directories, especially user Startup folders, and investigate any scheduled tasks that launch these files.
*   Educate users on the risks associated with installing software from untrusted sources, even if it appears to be a legitimate prompt from Microsoft ClickOnce.
