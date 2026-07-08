---
title: 'New Abuse of ClickOnce Technology: Enhanced Persistence and Stealth by Threat Actors'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to achieve persistent and stealthy execution of malicious payloads on Windows systems by leveraging legitimate processes and built-in update mechanisms, often initiated via user interaction with a deceptive link or file.
date: "2026-07-08T06:47:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - windows
  - endpoint
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first. This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persistence
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persistence
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
    evidence: every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of .appref-ms files in a user's Startup folder, a known persistence mechanism for malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are increasingly exploiting Microsoft's ClickOnce application deployment technology to deliver and maintain malware on target systems, a technique detailed by CrowdStrike. This abuse leverages ClickOnce's inherent user-friendliness, requiring minimal user interaction for deployment, thus bypassing common security mechanisms like email filters. Attackers benefit from the general lack of awareness regarding `.application` files, often deceiving users into initiating software installation with a single click. A significant advantage for adversaries is that ClickOnce applications do not require elevated privileges for installation, enabling compromise of standard user accounts. Furthermore, the technology's built-in update mechanism allows attackers to maintain remote access and periodically update their malicious payloads for purposes like changing Command and Control (C2) addresses, facilitating lateral movement, or performing data exfiltration. The execution of these malicious applications within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, along with legitimate UI displays, significantly enhances the stealth of these operations. This approach simplifies the delivery phase of attacks and complicates detection for security teams.

## Attack Chain

1.  **Initial Access**: Threat actors send phishing emails or host malicious web pages designed to convince targets to click on a link that initiates a ClickOnce application deployment.
2.  **Execution**: Upon user interaction (e.g., clicking a deceptive button or `.application` file), the ClickOnce application is deployed and the initial malicious payload is executed on the victim's Windows system.
3.  **Persistence (Offline Shortcut)**: The malicious ClickOnce application, if configured for offline availability, drops an `.appref-ms` shortcut file into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Persistence (Autostart)**: To ensure ongoing access, the attacker places the `.appref-ms` file into the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to periodically execute the `.appref-ms` file.
5.  **Defense Evasion (Process Masquerading)**: The malicious payload executes within legitimate Microsoft process trees, specifically observed using `rundll32.exe` and `dfsvc.exe`, and displays legitimate Microsoft user interface elements, making the activity appear benign.
6.  **Command and Control (Update Mechanism)**: The deployed ClickOnce application leverages its built-in update mechanism to fetch new malicious components, C2 instructions, or additional tools from an attacker-controlled server without requiring further user consent.
7.  **Impact**: Through the established persistence and C2, threat actors can maintain remote access, update their malware, initiate lateral movement within the network, or perform data exfiltration.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and execute arbitrary code on victim systems with high stealth. Without requiring elevated privileges, this technique expands the attack surface to include standard user accounts, which comprise the majority of enterprise endpoints. Successful exploitation can lead to prolonged unauthorized access, enabling attackers to continuously update their malware, facilitating command and control, lateral movement within the network, and ultimately, data exfiltration or other severe compromises. The broad targeting of Windows users across various sectors makes this a significant risk for any organization relying on Microsoft infrastructure.

## Recommendation

*   Enable comprehensive file creation/modification logging via Sysmon or similar EDR solutions to detect the creation of `.appref-ms` files in critical locations.
*   Deploy the Sigma rule `Detect_ClickOnce_Appref_Ms_Persistence` to your SIEM to alert on suspicious `.appref-ms` file creations in startup directories.
*   Implement strong application control policies that restrict the execution of unsigned or untrusted ClickOnce applications.
*   Educate users about the risks associated with unsolicited ClickOnce application deployments and suspicious links, particularly those bypassing typical attachment scrutiny.
