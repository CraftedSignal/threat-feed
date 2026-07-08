---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, leveraging its user-friendly deployment, lack of user scrutiny, and built-in update mechanism to deliver malware stealthily, achieve persistence without elevated privileges, and maintain remote access by bypassing traditional defenses.
date: "2026-07-08T06:08:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware
  - persistence
  - defense-evasion
  - windows
  - supply-chain-abuse
vendors:
  - Microsoft
products:
  - ClickOnce Applications
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persistence
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: ClickOnce applications for adversaries lies in the fact that they don’t require elevated privileges to be deployed. ... any user can install a ClickOnce app.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: ClickOnce applications can sometimes fly under the radar of security tools, creating an opportunity for threat actors to slip through traditional defenses.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Deployment Services Spawning Suspicious Processes
    description: Detects instances where the ClickOnce Deployment Services (dfsvc.exe) spawns known suspicious processes often used for command execution or scripting, indicating potential malware execution via ClickOnce abuse.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Persistence via Startup Folder (.appref-ms)
    description: Detects the creation of ClickOnce application reference files (.appref-ms) in user Startup folders, a known technique for achieving persistence without requiring elevated privileges.
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
rules_count: 2
---

Since at least June 2026, threat actors have intensified their abuse of Microsoft's ClickOnce technology to deliver and persist malware on target systems, as highlighted by recent CrowdStrike observations. This technique exploits ClickOnce's minimal user interaction requirement for deployment, which often bypasses traditional scrutiny applied to `.exe` files and common email filtering systems. Attackers leverage the fact that ClickOnce applications can be installed without administrator privileges, targeting standard user accounts that comprise most enterprise endpoints. A key new abuse involves the stealthy updating mechanism inherent in ClickOnce, allowing attackers to transform initially benign applications into malicious ones post-installation or to modify C2 infrastructure, deliver new payloads, and facilitate lateral movement. Execution occurs within legitimate Microsoft process trees like `rundll32.exe` and `dfsvc.exe`, further aiding defense evasion. This method creates a powerful, low-barrier-to-entry attack vector that poses a significant challenge for security teams due to its inherent legitimacy and update capabilities.

## Attack Chain

1.  **Initial Access**: Threat actor crafts a malicious ClickOnce application and hosts it on a controlled server, then delivers a link (e.g., via phishing email or compromised website) to the target.
2.  **User Execution**: The victim clicks the provided link, initiating the ClickOnce deployment process with minimal user prompts, often bypassing traditional user awareness of software installation.
3.  **Application Deployment**: The ClickOnce application is deployed onto the user's system, leveraging legitimate Microsoft processes such as `dfsvc.exe` (ClickOnce Deployment Services) for execution.
4.  **Initial Payload Execution**: The deployed ClickOnce application executes its embedded malicious payload, typically within the process context of `rundll32.exe`, without requiring elevated administrative privileges.
5.  **Persistence Establishment**: The threat actor establishes persistence by dropping an `.appref-ms` shortcut file into the user's `Start Menu\Programs\Startup\` folder, ensuring the malicious application restarts with the system.
6.  **Remote Access & Command and Control (C2)**: The ClickOnce application establishes an initial C2 channel, enabling remote access and data exfiltration.
7.  **Malware Update & Lateral Movement**: The attacker leverages the built-in ClickOnce update mechanism to push new malicious components or modify existing ones (e.g., updating C2 addresses, delivering additional malware, or enabling lateral movement) without further user interaction.
8.  **Impact**: Maintenance of long-term remote access, continuous delivery of updated malware, potential for data exfiltration, and significant compromise of the target system and network.

## Impact

If successful, this ClickOnce abuse leads to the stealthy execution and persistence of malware on targeted systems, allowing threat actors to maintain remote access and continually update their malicious capabilities. The attacker can deliver new payloads, alter command and control infrastructure, and facilitate lateral movement within the compromised network. This method enables the circumvention of security controls, as the initial deployment and subsequent updates occur within legitimate Microsoft processes and leverage trusted system functionalities. While specific victim numbers are not provided, the general nature of this technique suggests a broad applicability across various sectors, impacting any organization where ClickOnce applications are implicitly trusted or not adequately monitored. The primary consequence is sustained unauthorized access and control over enterprise endpoints.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related activities.
*   Enable Sysmon process-creation logging to capture parent-child process relationships for rules targeting `dfsvc.exe` and `rundll32.exe`.
*   Enable Sysmon file-event logging (Event ID 11) to detect the creation of `.appref-ms` files in persistence locations.
*   Educate users on the risks associated with unexpected software installation prompts, especially those leveraging technologies like ClickOnce, and to report suspicious links or files.
