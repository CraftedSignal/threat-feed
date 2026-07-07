---
title: 'New Abuse of ClickOnce Technology: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology to gain initial access, execute malicious code, and achieve persistence on Windows systems by leveraging its user-friendly deployment process, low privilege requirements, stealthy execution within legitimate Microsoft process trees, and built-in update mechanism for ongoing remote access and malware updates.
date: "2026-07-05T07:15:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - execution
  - windows
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input.
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce AppRef-ms Persistence via Startup Folder
    description: Detects the creation of .appref-ms files in a user's Startup folder, a known persistence mechanism for malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: ClickOnce AppRef-ms Persistence via Scheduled Task Creation
    description: Detects the creation of scheduled tasks that launch .appref-ms files, indicating a potential persistence mechanism for malicious ClickOnce applications.
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

Threat actors are actively exploiting Microsoft's ClickOnce technology to bypass traditional security defenses and establish persistent access on target systems. This abuse, documented by CrowdStrike in June 2026, capitalizes on the minimal user interaction required for ClickOnce deployments, allowing malicious applications to slip past mail filters and user scrutiny. Attackers can trick users into clicking web buttons or `.application` files, leading to the execution of malicious payloads that run discreetly within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`. A key aspect of this abuse is the `.appref-ms` file, which enables persistence by being placed in the Start Menu's Startup folder or via scheduled tasks, and facilitates built-in updating capabilities. This mechanism allows adversaries to maintain remote access and update their malware (e.g., changing C2 addresses, enabling lateral movement) without further user authorization, posing a significant challenge for defenders.

## Attack Chain

1.  **Initial Access**: Threat actors convince targets to initiate a ClickOnce deployment by clicking a deceptive web button or a malicious `.application` file.
2.  **Deployment & Execution**: Upon user interaction, the ClickOnce application is deployed, and the embedded malicious payload executes. This execution often occurs within legitimate Microsoft process trees, such as `rundll32.exe` or `dfsvc.exe`, which enhances stealth.
3.  **Persistence (AppRef-ms Dropped)**: If the ClickOnce application is configured for offline availability, a malicious `.appref-ms` shortcut file is dropped into the Windows Start Menu, typically under `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`.
4.  **Persistence (Autostart Configuration)**: The attacker establishes persistence by strategically placing the `.appref-ms` file in the Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or by creating a scheduled task that launches the `.appref-ms` file.
5.  **Malicious Update Staged**: The attacker, having control over the ClickOnce deployment server, stages a malicious update for the installed application.
6.  **Update Execution**: When the user next launches the ClickOnce application (either via the `.appref-ms` shortcut or an autostart mechanism), the ClickOnce components automatically fetch and install the staged malicious update without requiring additional user authorization.
7.  **Impact**: The newly installed malicious payload executes, granting the attacker capabilities such as remote access, modification of command and control (C2) infrastructure, or facilitating lateral movement within the network.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common initial access defenses, execute malicious code with low user interaction, and establish resilient persistence. This includes circumventing mailbox filtering systems and exploiting a general lack of user and security tool awareness regarding `.application` files. If successful, attackers gain reliable remote access to compromised endpoints, can update their malware at will (e.g., for changing C2 addresses or deploying new capabilities), and can use the compromised system for lateral movement within the network. The stealthy execution within legitimate Microsoft processes further complicates detection, enabling adversaries to operate undetected for extended periods.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Enable Sysmon file creation logging to activate `ClickOnce_AppRef_Startup_Persistence` rule.
*   Ensure process creation logging (e.g., Sysmon Event ID 1) is enabled to detect scheduled task creations relevant to `ClickOnce_AppRef_Scheduled_Task_Persistence`.
*   Educate users about the risks of installing software from untrusted sources, especially when prompted to click buttons or open `.application` files directly from web pages.
