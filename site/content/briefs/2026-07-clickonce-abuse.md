---
title: New Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are leveraging Microsoft's ClickOnce deployment technology to bypass traditional security controls, establish persistent access, and deploy malware by convincing users to click malicious application links, facilitating execution through legitimate Microsoft processes and silent updates.
date: "2026-07-04T09:31:41Z"
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
  - deployment
vendors:
  - Microsoft
products:
  - Microsoft ClickOnce Technology
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce Deployment Service Spawning Suspicious Processes
    description: Detects potentially malicious activity where dfsvc.exe (ClickOnce Deployment Service) spawns suspicious child processes indicative of payload execution or further compromise. This helps identify when a legitimate ClickOnce process is used to launch malware.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: ClickOnce .appref-ms File Creation in Startup Folder
    description: Detects the creation of .appref-ms files in a user's Startup folder, which is a common persistence mechanism for ClickOnce-based malware. This indicates an attempt to automatically launch a ClickOnce application upon user login.
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

CrowdStrike has identified new methods by which threat actors are abusing Microsoft's ClickOnce deployment technology to facilitate initial access and persistence. This abuse leverages the inherent user-friendliness and low-privilege installation of ClickOnce applications, enabling actors to bypass traditional email and endpoint security defenses. Adversaries can convince users to click seemingly benign links or `.application` files, leading to the deployment and execution of malicious payloads. The built-in update mechanism of ClickOnce further allows attackers to remotely update their malicious applications, ensuring persistent access and evolving capabilities. The use of legitimate Microsoft processes (`rundll32.exe` and `dfsvc.exe`) for execution aids in defense evasion, as these activities blend with normal system operations. This technique is particularly attractive to adversaries due to a general lack of awareness among users and security tools regarding ClickOnce, simplifying initial compromise and long-term presence on target systems.

## Attack Chain

1.  **Initial Access - User Execution**: Threat actors lure a user (e.g., via phishing email, compromised website, or malicious download) into clicking a link or executing a `.application` file that points to a malicious ClickOnce application deployment manifest.
2.  **Execution - ClickOnce Deployment**: Upon user interaction, the ClickOnce deployment service (`dfsvc.exe`) initiates, downloading the application manifest and components.
3.  **Execution - Payload Execution**: The malicious payload embedded within the ClickOnce application is executed, often through `rundll32.exe` or other legitimate system binaries spawned by `dfsvc.exe`.
4.  **Persistence - Autostart Execution**: If configured for offline availability, the malicious ClickOnce application drops an `.appref-ms` shortcut file into a common persistence location, such as the user's Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or is configured via a scheduled task.
5.  **Defense Evasion - Masquerading**: The malicious payload executes within the context of legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), making it harder to detect and distinguish from benign system activity.
6.  **Command and Control - Update Mechanism Abuse**: The attacker, maintaining control of the deployment server, pushes malicious updates to the ClickOnce application. When the user next launches the application (e.g., via the `.appref-ms` shortcut), the updated malicious components are silently downloaded and executed, re-establishing or evolving remote access.
7.  **Impact**: The attacker gains persistent remote access to the compromised system, enabling subsequent actions such as data exfiltration, lateral movement, or deployment of additional malware like ransomware or info-stealers.

## Impact

The described abuse of ClickOnce technology significantly enhances threat actors' ability to bypass common email and endpoint security controls, leading to successful initial compromise and resilient persistent access. By circumventing the need for elevated privileges and leveraging a less scrutinized deployment mechanism, adversaries can effectively target a broad range of standard user accounts across various enterprise environments. If successful, this can result in unauthorized remote access to victim systems, the stealthy exfiltration of sensitive organizational data, deployment of secondary malware, and the establishment of robust, self-updating command and control infrastructure. The widespread lack of awareness regarding ClickOnce security implications among users and security tools amplifies the potential for widespread and impactful compromise across diverse sectors.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, focusing on `dfsvc.exe` child processes and `.appref-ms` file creation.
*   Enable comprehensive logging for `process_creation` events (e.g., via Sysmon) to capture `dfsvc.exe` activity and its spawned child processes.
*   Enable `file_event` logging for file creation/modification activities in common persistence directories (e.g., Startup folders) to detect `.appref-ms` file placements.
*   Educate users on the risks associated with executing `.application` files or clicking links that initiate software installations outside of sanctioned channels.
