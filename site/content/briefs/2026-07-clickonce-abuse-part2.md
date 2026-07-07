---
title: New Abuse of ClickOnce Technology for Malware Distribution and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology to distribute malware, gain persistence, and maintain remote access by leveraging its user-friendly deployment, which requires minimal user interaction and can bypass traditional defenses due to a general lack of awareness, allowing attackers to install applications without elevated privileges and use the built-in update mechanism to push malicious payloads within legitimate Microsoft processes like rundll32.exe and dfsvc.exe.
date: "2026-07-07T12:10:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - malware
  - windows
  - endpoint-security
  - remote-access
vendors:
  - Microsoft
products:
  - ClickOnce
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
    evidence: users rarely realize that clicking a webpage button can trigger software installation... This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
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
    evidence: creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism... This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of ClickOnce application reference files (.appref-ms) within a user's Startup folder, a known persistence mechanism for malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Scheduled Task Creation for ClickOnce .appref-ms File
    description: Detects the creation of a scheduled task that executes a ClickOnce application reference file (.appref-ms), indicating a potential persistence mechanism for malicious ClickOnce applications.
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

Threat actors are increasingly exploiting Microsoft's ClickOnce deployment technology, as detailed in CrowdStrike's Part 2 analysis, to bypass traditional security defenses and achieve stealthy malware distribution and persistence. This abuse, observed in ongoing campaigns, leverages the inherent user-friendliness of ClickOnce, which allows applications to be installed with minimal user interaction and without requiring elevated privileges. Attackers entice targets to click malicious links or open `.application` files, enabling the execution of payloads within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, thereby evading detection. A significant advantage for attackers is the built-in updating mechanism of ClickOnce, which they can hijack to push new malicious payloads, maintain remote access, and change Command and Control (C2) infrastructure over time. This approach allows malware to "fly under the radar" compared to more scrutinized executable files, making it a potent vector for initial access and long-term compromise.

## Attack Chain

1.  **Initial Access**: The threat actor lures a user, often through phishing emails or drive-by downloads, to click a malicious link or execute a weaponized `.application` file, initiating a ClickOnce deployment.
2.  **Application Deployment & Execution**: The ClickOnce application is deployed without requiring administrative privileges, and the embedded malicious payload is executed.
3.  **Stealthy Execution**: The malicious payload's code runs within legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`, helping it evade detection and appear as benign system activity.
4.  **Persistence - Startup Folder**: To ensure continuous access, the attacker configures the deployed ClickOnce application to be available offline, causing an `.appref-ms` shortcut file to be dropped into the user's `Start Menu\Programs\Startup` folder.
5.  **Persistence - Scheduled Task**: Alternatively or additionally, the attacker creates a scheduled task to regularly execute the `.appref-ms` file, further solidifying persistence.
6.  **Command and Control via Updates**: The built-in ClickOnce updating mechanism is leveraged to push new malicious components, change Command and Control (C2) server addresses, or deliver additional tools for lateral movement and data exfiltration.
7.  **Impact**: The malicious application gains persistent access, can receive updated instructions and payloads, and performs actions such as data exfiltration or further compromise of the network.

## Impact

The abuse of ClickOnce technology leads to successful malware execution and persistence on targeted systems, typically without the need for administrative privileges, affecting a wide range of standard user accounts. Organizations that rely on traditional endpoint security measures, which often scrutinize `.exe` files but overlook `.application` files, are particularly vulnerable. If successful, this attack allows threat actors to establish long-term remote access, update their malware continuously, bypass network defenses, exfiltrate sensitive data, and potentially conduct lateral movement within the compromised environment. The stealthy execution within legitimate Microsoft processes significantly prolongs detection times and increases the overall impact of a breach.

## Recommendation

*   Deploy the provided Sigma rules to detect suspicious ClickOnce persistence mechanisms in your SIEM.
*   Configure process creation logging (e.g., Sysmon Event ID 1) to capture `schtasks.exe` command lines for `Sigma Rule 1`.
*   Ensure file creation/modification logging (e.g., Sysmon Event ID 11) is enabled for `Sigma Rule 2`.
*   Implement strong application control policies to restrict the execution of unsigned ClickOnce applications or those from untrusted sources.
*   Educate users on the dangers of clicking untrusted links and opening `.application` files from unknown senders.
