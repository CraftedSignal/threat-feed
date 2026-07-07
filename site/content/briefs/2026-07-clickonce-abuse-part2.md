---
title: Threat Actors Abuse Microsoft ClickOnce for Stealthy Persistence and Malware Updates
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are weaponizing Microsoft's ClickOnce technology to deploy malicious applications with minimal user interaction, establish stealthy persistence through `.appref-ms` files, and maintain remote access via the built-in update mechanism, bypassing traditional security controls and executing within legitimate Windows processes.
date: "2026-07-07T07:50:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - initial-access
  - windows
vendors:
  - Microsoft
products:
  - Microsoft ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: While .exe files are heavily scrutinized and controlled in most environments, .application files can sometimes fly under the radar of security tools, creating an opportunity for threat actors to slip through traditional defenses.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) within a user's Startup folder, indicating an attempt to establish persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation for ClickOnce .appref-ms Execution
    description: Detects the creation or modification of a scheduled task that executes a ClickOnce application shortcut (.appref-ms), used by attackers for persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce technology to deploy and maintain malicious applications with high stealth and persistence. This abuse leverages ClickOnce's user-friendly deployment, which requires minimal interaction, often just a single click, and bypasses common security mechanisms like mailbox filters. The technique does not require elevated privileges, making standard user accounts vulnerable. A key aspect of this abuse involves the `.appref-ms` files, which are shortcuts dropped in the Windows Start Menu, enabling attackers to establish persistence by placing them in the Startup folder or via scheduled tasks. The built-in update mechanism allows attackers to push malicious updates from controlled deployment servers, effectively changing C2 addresses, moving laterally, or deploying new malware without further user prompts. Malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, increasing the stealth of these operations and making detection challenging for tools that solely rely on process reputation.

## Attack Chain

1.  **Initial Access**: A user is convinced to initiate the deployment of a malicious ClickOnce application, often via a deceptive link or by opening a `.application` file.
2.  **Execution & Installation**: The ClickOnce application is deployed on the user's system without requiring administrator privileges, creating necessary application files and potentially a `.appref-ms` shortcut in the user's Start Menu.
3.  **Initial Payload Execution**: An initial malicious payload runs stealthily within legitimate Microsoft ClickOnce host processes, specifically `rundll32.exe` or `dfsvc.exe`.
4.  **Persistence Establishment**: The attacker establishes persistence by either creating a new `.appref-ms` shortcut in the user's Startup folder or by configuring a scheduled task to regularly launch the `.appref-ms` file.
5.  **Malicious Update Check**: Upon subsequent launch of the ClickOnce application (e.g., via the persisted shortcut), the application automatically checks an attacker-controlled deployment server for available updates.
6.  **Payload Update & Re-execution**: The attacker delivers a malicious update through the ClickOnce update mechanism, which is then downloaded and executed without further user interaction, enabling continued command and control, lateral movement, or additional malware deployment.

## Impact

Organizations face significant risks from this ClickOnce abuse, including persistent unauthorized access to endpoints, potential data exfiltration, and the unhindered deployment of further malware such as ransomware or credential stealers. The ease of deployment, coupled with the lack of user and security tool awareness regarding `.application` files, allows attackers to bypass traditional defenses. Since no elevated privileges are required, standard user accounts, which comprise the majority of enterprise endpoints, become viable targets, leading to widespread compromise across an organization's user base. The execution within legitimate Microsoft processes further complicates detection and enables long-term, stealthy operations.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable process creation logging (e.g., Sysmon Event ID 1) and scheduled task creation/modification logging (e.g., Sysmon Event ID 12, 13) to capture the behaviors targeted by the rules.
*   Implement strong application control policies to restrict the execution of unsigned or untrusted ClickOnce applications, or to block `.application` files from unknown sources.
*   Educate users on the risks associated with clicking on untrusted links or opening `.application` files from unknown senders to mitigate the initial access vector.
*   Monitor `rundll32.exe` and `dfsvc.exe` activity for unusual network connections or module loads, especially when originating from ClickOnce application cache directories.
