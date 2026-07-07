---
title: 'New Abuse of the ClickOnce Technology: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's legitimate ClickOnce technology to deliver malware, establish persistence via `.appref-ms` files in startup folders, and execute payloads without administrative privileges, often bypassing traditional security defenses and leveraging built-in update mechanisms for ongoing control.
date: "2026-07-07T14:35:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - defense-evasion
  - microsoft-windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app... This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder .appref-ms File
    description: Detects the creation of an .appref-ms file within a user's Startup folder, a known method for ClickOnce application persistence used by threat actors.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are actively leveraging Microsoft's ClickOnce deployment technology as a vector for malware delivery, persistence, and execution, according to recent observations by CrowdStrike. This abuse is attractive to attackers due to ClickOnce's user-friendly deployment process, which requires minimal user interaction and no administrative privileges, allowing malware to be installed even on standard user accounts. Furthermore, the general lack of awareness regarding `.application` files compared to `.exe` files enables these attacks to bypass traditional security scrutiny. Attackers also benefit from the stealth provided by execution within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, and can maintain persistent access and update their payloads using ClickOnce's built-in update mechanism. This approach simplifies the delivery phase of the kill chain and poses a significant challenge for defenders.

## Attack Chain

1.  **Social Engineering / Initial Access**: Threat actors distribute malicious `.application` files or lure users to websites containing misleading buttons that initiate ClickOnce deployment, often via phishing campaigns or compromised legitimate sites.
2.  **User Execution**: A user is tricked into clicking the malicious web button or directly launching the `.application` file, which triggers the ClickOnce deployment process on their system.
3.  **Application Deployment**: The ClickOnce framework installs the attacker's malicious application, which can often occur with minimal user prompts and without requiring elevated administrative privileges.
4.  **Persistence Establishment**: The attacker configures the deployed ClickOnce application to maintain persistence, typically by placing an `.appref-ms` shortcut file in the user's Startup folder (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or by creating a scheduled task to regularly execute the `.appref-ms` file.
5.  **Stealthy Execution**: The malicious payload is executed by legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, making its activity harder to distinguish from normal system operations and aiding in defense evasion.
6.  **Command and Control / Updates**: The attacker leverages ClickOnce's inherent update mechanism to remotely push new malicious components, modify C2 infrastructure, or update existing payloads without requiring further user interaction or re-deployment.
7.  **Impact**: The persistent, stealthy execution of the malicious application enables various attacker objectives, including remote access, lateral movement, data exfiltration, or further compromise of the victim's environment.

## Impact

The abuse of ClickOnce technology leads to unauthorized software installation and persistence on enterprise endpoints without requiring administrative privileges, effectively bypassing traditional security controls. This method allows threat actors to establish a foothold and maintain remote access through built-in update mechanisms, enabling continuous compromise. The stealthy execution within legitimate Microsoft processes complicates detection efforts, increasing the likelihood of successful data exfiltration, lateral movement, or deployment of additional malware. The pervasive lack of user and security tool awareness regarding ClickOnce applications makes organizations highly susceptible to these attacks.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the creation of suspicious `.appref-ms` files in common persistence locations.
*   Enable Sysmon file creation logging (`FileCreate` event ID 11) for `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` to identify `.appref-ms` file persistence.
*   Educate users on the risks associated with clicking on unknown web buttons or opening `.application` files, especially those not from trusted sources.
*   Implement application control policies to restrict execution of unsigned or untrusted ClickOnce applications where possible.
