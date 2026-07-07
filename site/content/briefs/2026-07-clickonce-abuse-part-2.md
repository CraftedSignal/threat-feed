---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to bypass traditional security controls, establish persistence, and execute malware on Windows systems with minimal user interaction and low privileges, leveraging built-in update mechanisms and legitimate Microsoft processes.
date: "2026-07-06T07:45:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - endpoint-security
  - persistence
  - defense-evasion
  - windows
  - clickonce
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed... Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input.
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
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
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
  - title: ClickOnce .appref-ms File Creation in Startup Folder
    description: Detects the creation of .appref-ms files in a user's Windows Startup folder, a common method for achieving persistence with malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Scheduled Task Creation for ClickOnce .appref-ms
    description: Detects the creation of scheduled tasks that explicitly reference and launch ClickOnce .appref-ms files, indicating a persistence mechanism.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Registry Run Key Modification for ClickOnce .appref-ms
    description: Detects modifications to Windows Registry Run keys to automatically launch ClickOnce .appref-ms files, indicating a persistence attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Threat actors are actively abusing Microsoft's ClickOnce technology, a legitimate Windows application deployment mechanism, to bypass traditional security controls and establish persistence on target systems. This "new abuse," observed by CrowdStrike, leverages ClickOnce's user-friendliness, requiring minimal interaction to deploy malware through malicious `.application` files or misleading webpage buttons. Unlike traditional executable installers, `.application` files often evade scrutiny, allowing payloads to execute with low privileges within trusted Microsoft processes like `rundll32.exe` and `dfsvc.exe`. The attackers exploit ClickOnce's built-in update mechanism to push new malicious code without further user prompts and achieve long-term persistence by placing `.appref-ms` shortcut files in the Startup folder or creating scheduled tasks. This method provides a stealthy and reliable way to maintain remote access, update malware, and facilitate lateral movement.

## Attack Chain

1.  **Initial Access**: User is lured into clicking a malicious link or button on a webpage, or directly opens a malicious `.application` file delivered via methods bypassing mailbox filtering systems.
2.  **Execution (ClickOnce Initiation)**: The user interaction initiates a ClickOnce application deployment, prompting minimal user input due to the technology's design.
3.  **Execution (Payload Delivery)**: The ClickOnce application downloads and executes the malicious payload without requiring elevated administrative privileges.
4.  **Defense Evasion (Process Masquerading)**: The malicious payload executes within legitimate Microsoft process trees, specifically involving `rundll32.exe` and `dfsvc.exe`, increasing the stealthiness of the operation and evading scrutiny.
5.  **Persistence (Shortcut Deployment)**: If configured for offline availability, an application reference file (`.appref-ms`) is dropped in the Windows Start Menu, providing a shortcut to the installed application.
6.  **Persistence (Update Mechanism)**: The attacker pushes malicious updates to their controlled deployment server, which are automatically fetched and executed by the ClickOnce client when the user next launches the application via its `.appref-ms` shortcut, without further user authorization.
7.  **Persistence (Autostart)**: The attacker places the `.appref-ms` file in the user's Startup folder or creates a scheduled task to automatically launch the malicious ClickOnce application upon system boot or other triggers.
8.  **Impact**: The attacker establishes persistent remote access, maintains control over the compromised system, and can update their malware for further objectives like changing Command and Control (C2) addresses, performing lateral movement, or exfiltrating data.

## Impact

The observed abuse of ClickOnce allows threat actors to establish persistent remote access to compromised systems, bypassing security tools and maintaining control through silent updates to their malicious applications. This enables them to modify Command and Control (C2) infrastructure, perform lateral movement within the victim network, and execute further actions without requiring elevated privileges. While specific victim counts or industry sectors are not detailed in this research, the method's effectiveness in evading defenses and its inherent stealth pose a significant risk of data exfiltration and widespread system compromise across any Windows environment where ClickOnce applications are permitted.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Ensure comprehensive `file_event` logging is enabled to capture `.appref-ms` file creations, particularly outside of standard application directories.
*   Configure `process_creation` logging for `schtasks.exe` to identify new scheduled tasks that may initiate malicious ClickOnce applications.
*   Enable `registry_set` logging for `HKEY_CURRENT_USER` and `HKEY_LOCAL_MACHINE` Run keys to detect persistence attempts via ClickOnce `.appref-ms` entries.
