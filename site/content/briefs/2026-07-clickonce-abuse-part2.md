---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively leveraging Microsoft's ClickOnce technology, specifically targeting the user-friendly deployment and built-in update mechanisms, to deliver malware, achieve persistence, and evade detection by executing payloads within legitimate Microsoft processes and creating malicious shortcuts in system startup locations.
date: "2026-07-04T11:06:48Z"
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
  - malware-delivery
  - initial-access
  - microsoft
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: users rarely realize that clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first. This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder
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
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder - appref-ms File Creation
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) within a user's Startup folder, which adversaries abuse for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation Executing appref-ms File
    description: Detects the use of 'schtasks.exe' to create a scheduled task that executes a ClickOnce application shortcut (.appref-ms file), indicating a persistence mechanism.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are increasingly abusing Microsoft's ClickOnce application deployment technology to facilitate malware delivery, establish persistence, and bypass traditional security defenses. This novel exploitation capitalizes on ClickOnce's minimal user interaction requirement for installation, allowing `.application` files to sometimes evade scrutiny compared to `.exe` files. Attackers benefit from the fact that ClickOnce applications do not require elevated privileges for deployment, expanding their target base to standard user accounts. Furthermore, the technology's built-in updating mechanism is weaponized to maintain remote access and update malware payloads by pushing malicious updates to already installed applications. The legitimacy of the ClickOnce deployment process further aids evasion, as malicious code executes within seemingly benign Microsoft process trees (e.g., `rundll32.exe`, `dfsvc.exe`), making detection more challenging for security teams.

## Attack Chain

1.  **Initial Access / User Execution**: Threat actors craft phishing campaigns or deceptive web pages, convincing targets to click a link or open an `.application` file.
2.  **Application Deployment**: Upon user interaction, the ClickOnce deployment process is initiated, installing the malicious application on the user's system with minimal prompts.
3.  **Malicious Payload Execution**: The embedded malicious payload executes on the victim's machine, often within the context of legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, to blend in with normal system activity.
4.  **Persistence - .appref-ms Shortcut**: A malicious `.appref-ms` file, which is a shortcut to the ClickOnce application, is dropped onto the system.
5.  **Persistence - Autostart/Scheduled Task**: The `.appref-ms` file is strategically placed in the user's Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or configured as a scheduled task to ensure automatic execution upon reboot or at specific intervals.
6.  **Defense Evasion**: The use of legitimate ClickOnce processes and `.application` file types helps evade detection by traditional endpoint security solutions that scrutinize `.exe` files more heavily.
7.  **Command and Control / Update Mechanism Abuse**: The built-in ClickOnce update mechanism is exploited to push new, more malicious payloads or retrieve command and control (C2) instructions from attacker-controlled servers, maintaining long-term access.
8.  **Impact**: The persistent access facilitates further actions such as data exfiltration, deployment of additional malware (e.g., ransomware, infostealers), or lateral movement within the compromised network.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent footholds within targeted environments, leading to significant compromises. Once a malicious ClickOnce application is deployed, attackers can maintain remote access, exfiltrate sensitive data, and deploy secondary malware like ransomware or infostealers, bypassing security controls that might otherwise detect more traditional executable payloads. The stealthy nature of this technique, operating within legitimate Microsoft processes and leveraging built-in update mechanisms, increases the likelihood of prolonged presence and deeper infiltration before detection, impacting data confidentiality and system integrity across various sectors.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM/EDR to detect suspicious ClickOnce persistence mechanisms.
*   Enable comprehensive file system event logging (e.g., via Sysmon) to capture `.appref-ms` file creation and modification, particularly in startup directories.
*   Monitor `process_creation` events for `schtasks.exe` executions that involve `.appref-ms` files, which may indicate scheduled task persistence.
*   Educate users on the risks associated with clicking suspicious links and opening unfamiliar `.application` files, even if they appear to initiate a legitimate installation process.
