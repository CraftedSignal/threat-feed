---
title: Threat Actors Actively Abuse Microsoft ClickOnce for Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are increasingly leveraging Microsoft's ClickOnce technology to bypass traditional security defenses, simplify malware delivery, and establish persistence on target systems, allowing for remote access and continuous malware updates without requiring elevated privileges.
date: "2026-07-07T15:49:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - malware-delivery
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of a ClickOnce .appref-ms shortcut file in the Windows Startup folder, a common persistence mechanism for malicious ClickOnce applications. This is explicitly described as an abuse in the CrowdStrike report.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task
    description: Detects the creation of scheduled tasks that are configured to execute ClickOnce .appref-ms files, a known abuse for maintaining persistence and triggering malware updates. This explicitly uses `schtasks.exe` as described in the CrowdStrike report.
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

CrowdStrike has identified an increasing trend of threat actors abusing Microsoft's ClickOnce technology for malicious purposes, as detailed in their July 2026 report. This method significantly streamlines malware delivery by exploiting the user-friendly nature of ClickOnce deployments, which often requires only minimal user interaction (a "click once") to execute applications. The technique bypasses common security controls such as mailbox filtering and often goes undetected due to a general lack of scrutiny compared to traditional executable files (.exe). Threat actors achieve persistence by placing malicious `.appref-ms` files in the Windows Startup folder or by creating scheduled tasks, ensuring their malware runs on system reboots or at regular intervals. Execution occurs within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, lending an air of legitimacy to the malicious activity and complicating detection. This approach allows attackers to maintain remote access and update their malware from controlled deployment servers.

## Attack Chain

1.  **Initial Access (User Lure):** The attacker social engineers a victim, often through phishing, to click on a malicious link or button that initiates the download and deployment of a ClickOnce application.
2.  **Initial Execution (ClickOnce Deployment):** Upon user interaction, legitimate Microsoft ClickOnce components, specifically `dfsvc.exe` and `rundll32.exe`, are invoked to download and execute the initial malicious application, bypassing the need for administrator privileges.
3.  **Persistence (Startup Folder):** The deployed malicious ClickOnce application establishes persistence by creating an `.appref-ms` shortcut file in the user's Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`).
4.  **Persistence (Scheduled Task):** Alternatively, the malicious ClickOnce application creates a scheduled task designed to regularly open the `.appref-ms` file, ensuring recurring execution and checks for updates.
5.  **Defense Evasion (Process Masquerading):** The malicious payload executes under the guise of legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), making it harder for security tools and users to identify its nefarious nature.
6.  **Command and Control (Update Mechanism):** When the persisted `.appref-ms` file is launched, the ClickOnce framework automatically contacts an attacker-controlled deployment server, downloading and installing malicious updates or new components.
7.  **Impact (Remote Access & Malware Update):** The attacker leverages the inherent ClickOnce update mechanism to maintain remote access, modify existing malware, deliver new payloads, or change command and control (C2) infrastructure.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for entry for threat actors, enabling them to compromise standard user accounts which constitute the majority of enterprise endpoints. If successful, this attack vector results in the persistent presence of attacker-controlled malware on victim systems, facilitating remote access, data exfiltration, and the continuous deployment of additional malicious payloads. The stealthy execution within legitimate Microsoft processes means that organizations may face prolonged compromise before detection, leading to potential data breaches, operational disruption, and financial loss. The broad applicability of ClickOnce across Windows environments makes many organizations vulnerable to this attack.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable comprehensive file event logging for `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` to capture the creation of `.appref-ms` files as described in the "Detect ClickOnce `.appref-ms` Persistence via Startup Folder" rule.
*   Ensure process creation logging includes command-line arguments to detect suspicious `schtasks.exe` invocations as per the "Detect ClickOnce `.appref-ms` Persistence via Scheduled Task" rule.
*   Educate users on the risks associated with clicking suspicious links or downloading software from unverified sources, even if it appears to be a legitimate application deployment.
