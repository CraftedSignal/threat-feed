---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse
description: Threat actors are actively exploiting Microsoft's ClickOnce technology to facilitate malware delivery, achieve persistence, and evade traditional defenses by leveraging its user-friendly deployment, general lack of awareness, and ability to install applications without elevated privileges, often pushing malicious updates via .appref-ms files that execute within legitimate Microsoft process trees such as rundll32.exe and dfsvc.exe.
date: "2026-07-07T19:31:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - windows-exploitation
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
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: med
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) within the user's Startup folder, which is an observed technique for persistence.
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
    description: Detects the creation of a scheduled task (using schtasks.exe) that directly references a ClickOnce application shortcut (.appref-ms) for persistence.
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

CrowdStrike has observed new abuse of Microsoft's ClickOnce technology by threat actors for malware delivery, persistence, and defense evasion, as detailed in their July 2026 report, "New Abuse of the ClickOnce Technology, Part 2." This method bypasses common protection mechanisms by leveraging ClickOnce's low-friction installation, often requiring only one or two clicks from the target. Adversaries capitalize on the general lack of awareness regarding `.application` files and ClickOnce behavior, allowing them to install malicious payloads without requiring elevated privileges. A key abuse involves compromising legitimate ClickOnce application servers to push malicious updates via `.appref-ms` files, ensuring that even initially benign applications can become malicious, executing within trusted `rundll32.exe` and `dfsvc.exe` processes. This technique provides attackers with a stealthy and persistent method for maintaining remote access and updating their malware.

## Attack Chain

1.  Attacker crafts a malicious ClickOnce application or compromises a legitimate ClickOnce deployment server.
2.  Attacker entices a user to click a misleading link or button on a webpage, leading to the execution of a `.application` file.
3.  The ClickOnce application initiates its deployment and installation on the user's Windows system.
4.  A `.appref-ms` shortcut file is dropped into the user's Start Menu (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\`) for offline access or persistence.
5.  The attacker pushes a malicious update to the controlled or compromised ClickOnce deployment server.
6.  The user launches the ClickOnce application, either from the Start Menu shortcut, by placing the `.appref-ms` file in the Startup folder, or via a scheduled task.
7.  The ClickOnce components detect an available update, fetch the malicious payload from the deployment server, and execute it.
8.  The malicious payload executes under legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`, establishing persistence, command and control, or further compromise.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier to entry for attackers, as it enables the deployment of malware without requiring elevated privileges and often bypasses traditional security controls like mailbox filtering systems. If successful, attackers can achieve persistent access to target systems, execute arbitrary code within legitimate Microsoft processes, and maintain remote access with an easily updatable malicious payload. This stealthy execution can lead to data exfiltration, further network compromise, or the deployment of ransomware, impacting targeted organizations across various sectors. The lack of user awareness about ClickOnce installation mechanisms makes this an effective social engineering vector.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious persistence mechanisms leveraging `.appref-ms` files.
*   Enable Sysmon `ProcessCreate` and `FileCreate` event logging to activate the Sigma rules and gain visibility into process execution and file system changes related to ClickOnce.
*   Educate users on the risks associated with clicking links or opening `.application` files from untrusted sources, emphasizing that software installations should typically require explicit administrative consent.
*   Monitor for unsanctioned ClickOnce applications being installed or updated within your environment, focusing on their origins and behaviors.
