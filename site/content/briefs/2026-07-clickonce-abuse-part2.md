---
title: 'New Abuse of ClickOnce Technology: Persistence and Malware Delivery'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting the user-friendly ClickOnce application deployment technology to achieve stealthy malware delivery and persistence, leveraging `.appref-ms` files for automatic updates and execution within legitimate Microsoft process trees, bypassing traditional security controls.
date: "2026-07-07T17:13:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - windows
  - application-deployment
  - malware-delivery
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by [...] creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce shortcut (.appref-ms) file within a user's Startup folder, a known technique for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce Persistence via Scheduled Task
    description: Detects the creation of a scheduled task that launches a ClickOnce shortcut (.appref-ms) file, indicating potential persistence or malicious execution.
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

CrowdStrike has highlighted a novel abuse of Microsoft's ClickOnce technology, enabling threat actors to bypass security defenses and establish persistent access. This technique capitalizes on ClickOnce's user-friendly deployment, which requires minimal interaction, and the general lack of awareness regarding `.application` and `.appref-ms` file types compared to `.exe` files. Attackers can leverage the built-in updating mechanism to transform a benign, initially installed application into a malicious one without further user prompts. Furthermore, this method allows for payload execution within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, increasing stealth and making detection challenging. A key aspect of this new abuse involves using `.appref-ms` files, typically shortcuts to ClickOnce applications, for persistence by placing them in Windows Startup folders or integrating them into scheduled tasks.

## Attack Chain

1.  **Initial Access**: Threat actors craft deceptive emails or webpages, hosting a seemingly benign ClickOnce application (`.application` file).
2.  **User Execution**: The victim is enticed to click a link or button, initiating the download and installation of the ClickOnce application.
3.  **Installation & Shortcut Creation**: The ClickOnce application installs, creating a shortcut (`.appref-ms` file) in the user's Start Menu (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence Setup**: The threat actor, through a compromised deployment server or by manipulating the initial deployment, places the `.appref-ms` shortcut in a Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`) or configures a scheduled task to launch it periodically.
5.  **Malicious Update Push**: The threat actor pushes a malicious update to the ClickOnce application's deployment server, transforming the benign application into a malicious one.
6.  **Update Execution**: Upon subsequent launch of the application (either manually by the user or automatically via the persistence mechanism), the `.appref-ms` file triggers ClickOnce components to fetch and install the update.
7.  **Payload Execution**: The malicious update's payload executes within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, increasing stealth.
8.  **Impact**: The attacker gains remote access, establishes C2 communication, and can execute further commands or exfiltrate data.

## Impact

Successful exploitation of this ClickOnce abuse vector allows threat actors to establish robust and stealthy persistence on target systems without requiring elevated privileges. This bypasses common defenses like email filters and traditional application whitelisting, as the initial installation might appear legitimate and the subsequent malicious updates occur silently. The impact includes sustained remote access, enabling command and control, lateral movement within the network, and data exfiltration. Since this targets common enterprise endpoints, a wide range of organizations across various sectors could be affected, leading to potential data breaches, operational disruption, and financial losses.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, focusing on detecting `.appref-ms` file creation in unexpected locations and suspicious scheduled tasks.
*   Enable comprehensive file system monitoring for the creation of `.appref-ms` files outside of standard ClickOnce application directories, specifically targeting `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` using the `Detect ClickOnce Persistence via Startup Folder` rule.
*   Enable process creation logging, especially for `schtasks.exe` and PowerShell, to monitor for the creation of new scheduled tasks that launch `.appref-ms` files, as highlighted by the `Detect ClickOnce Persistence via Scheduled Task` rule.
*   Educate users about the risks associated with installing software from untrusted sources, even seemingly innocuous applications, and the nature of ClickOnce deployments.
