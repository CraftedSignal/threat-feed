---
title: 'New Abuse of ClickOnce Technology: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are actively abusing Microsoft's ClickOnce technology, leveraging its user-friendly deployment, lack of security awareness, and non-elevated privilege requirements to facilitate initial access, execute malware via legitimate processes (`rundll32.exe`, `dfsvc.exe`), and establish persistence through `.appref-ms` files in startup folders or scheduled tasks, allowing for reliable remote access and malware updates.
date: "2026-07-03T23:56:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - initial-access
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
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce appref-ms Persistence in Startup Folder
    description: Detects the creation of .appref-ms files in the Windows Startup folder, a common method for threat actors to establish persistence using ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation Referencing ClickOnce appref-ms
    description: Detects when schtasks.exe is used to create a scheduled task that references an .appref-ms file, indicating potential ClickOnce persistence.
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

Threat actors are increasingly exploiting Microsoft's ClickOnce deployment technology, a mechanism designed for easy installation of desktop applications, for malicious purposes. This abuse, detailed by CrowdStrike in June 2026, capitalizes on several features: minimal user interaction for deployment, a general lack of awareness regarding `.application` files compared to `.exe` files, and the ability to install applications without requiring administrator privileges. Attackers can trick users into deploying malicious ClickOnce applications, which then execute within legitimate Microsoft process trees (like `rundll32.exe` and `dfsvc.exe`), increasing stealth. A critical aspect of this abuse is the `.appref-ms` file, which is dropped during installation and can be used for persistence by placing it in the Startup folder or creating scheduled tasks, effectively turning the ClickOnce application into a persistent backdoor with built-in update capabilities for remote access and malware evolution.

## Attack Chain

1.  **Initial Access**: Threat actors deliver a malicious ClickOnce application, often via a deceptive link or `.application` file, convincing a user to initiate deployment.
2.  **Execution (Initial)**: The user clicks the link or file, triggering the ClickOnce deployment process, which executes without requiring administrator privileges, bypassing typical `.exe` scrutiny.
3.  **Payload Delivery**: The ClickOnce application installs, and the embedded malicious payload is delivered to the victim system.
4.  **Persistence**: An `.appref-ms` file, which acts as a shortcut to the ClickOnce app, is strategically placed in the user's Start Menu, Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), or referenced by a newly created scheduled task.
5.  **Execution (Malicious)**: The malicious payload executes within legitimate Microsoft process trees, specifically observed under `rundll32.exe` and `dfsvc.exe`, to evade detection.
6.  **Remote Access/Update**: Upon subsequent execution of the persisted `.appref-ms` file, the ClickOnce application's built-in update mechanism fetches new components from an attacker-controlled server, allowing the threat actor to maintain remote access, update malware, change C2 addresses, or facilitate lateral movement.
7.  **Impact/Exfiltration**: The updated malware then carries out its final objective, such as further system compromise, data exfiltration, or deployment of additional malicious tools.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and execute malware with high stealth, potentially compromising a wide range of enterprise endpoints. By bypassing traditional security scrutiny and administrative privilege requirements, attackers can significantly lower the barrier to entry for their campaigns. If successful, this can lead to sustained remote access, the ability to continually update and evolve malware on compromised systems, facilitate lateral movement within a network, and ultimately result in data theft, further system damage, or ransomware deployment. While specific victim counts are not provided, the general lack of awareness among users and security tools suggests a broad potential impact across targeted organizations.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence and execution.
*   Enable file creation logging (e.g., via Sysmon Event ID 11) to monitor for `.appref-ms` files in `Startup` folders.
*   Enable process creation logging (e.g., via Sysmon Event ID 1) to monitor `schtasks.exe` command lines for references to `.appref-ms` files.
*   Educate users about the risks of clicking on `.application` files or suspicious web links that initiate software installations.
