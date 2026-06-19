---
title: Threat Actors Abuse ClickOnce for Stealthy Malware Delivery and Persistence
slug: 2026-06-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce deployment technology, leveraging its user-friendly installation and update mechanisms to deliver malware, bypass security controls, and achieve persistence on Windows systems, as detailed in a June 2026 CrowdStrike report.
date: "2026-06-19T05:18:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - malware-delivery
  - defense-evasion
  - windows
vendors:
  - Microsoft
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .application file download from webserver
    description: Detects attempts to download ClickOnce .application manifest files from a web server, which can be an initial access vector for malicious ClickOnce deployments.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1204
      - T1566.001
    data_sources:
      - webserver
  - title: Detect .appref-ms file creation (ClickOnce Persistence)
    description: Detects the creation of .appref-ms files, which are shortcuts created by ClickOnce for installed applications, providing a persistence mechanism that can be leveraged by attackers to re-execute malicious payloads, especially after updates.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547.009
    data_sources:
      - file_event
      - windows
  - title: Detect suspicious child processes of dfsvc.exe
    description: Detects child processes spawned by dfsvc.exe (ClickOnce Application Deployment Support Service) that are not typically associated with legitimate ClickOnce application execution, indicating potential abuse for malicious payload execution or C2.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are actively abusing Microsoft's ClickOnce deployment technology to bypass security controls, achieve persistence, and deliver malicious payloads. This technique, highlighted in a June 2026 CrowdStrike report, leverages the user-friendly nature of ClickOnce applications and a general lack of awareness about their security implications. Attackers can trick users into installing malicious applications that don't require administrative privileges, often through phishing or misleading web buttons. A critical vector involves exploiting the ClickOnce update mechanism, where a benign installed application is later updated with malicious components when the user re-launches it via an `.appref-ms` shortcut. This provides a stealthy and persistent method for malware delivery and command and control, as execution occurs within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, making detection challenging.

## Attack Chain

1.  **Initial Access / User Execution**: The attacker socially engineers a target, often via a malicious link on a phishing page or email, convincing them to click a button or link that initiates a ClickOnce application download.
2.  **Deployment**: Upon user interaction, a `.application` file is downloaded, and the ClickOnce application is installed without requiring administrator privileges.
3.  **Initial Execution**: The installed ClickOnce application is launched, with its payload executing within legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`.
4.  **Persistence (Shortcut Creation)**: For offline access, an `.appref-ms` shortcut file is dropped in the user's Start Menu (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) allowing subsequent launches.
5.  **Update Mechanism Abuse**: The attacker, controlling the deployment server, pushes a malicious update to the previously installed ClickOnce application.
6.  **Persistent Execution**: When the user re-launches the application via the `.appref-ms` shortcut, the malicious update is fetched, downloaded, and executed automatically without further user prompts.
7.  **Command and Control / Impact**: The malicious updated payload establishes remote access, facilitates command and control, enables lateral movement, or exfiltrates data from the compromised system.

## Impact

The impact of successful ClickOnce abuse includes unauthorized remote access to compromised systems, persistent command and control capabilities for threat actors, and a foothold for further malicious activities such as lateral movement, data exfiltration, or the deployment of additional malware like ransomware. Because these applications install without administrative privileges, standard users can inadvertently expose the organization. The stealthy execution within legitimate processes makes these attacks difficult to detect, increasing dwell time and potential damage across various sectors susceptible to social engineering.

## Recommendation

*   Enable comprehensive web server logging to detect and alert on downloads of `.application` files, as highlighted in the 'Detect ClickOnce .application file download' Sigma rule.
*   Implement endpoint detection and response (EDR) solutions capable of monitoring `file_event` and `process_creation` logs, specifically tracking the creation of `.appref-ms` files and suspicious child processes of `dfsvc.exe`.
*   Deploy the 'Detect .appref-ms file creation' Sigma rule to baseline ClickOnce installations and identify anomalies in file creation locations or parent processes.
*   Utilize the 'Detect suspicious child processes of dfsvc.exe' Sigma rule in your SIEM to identify unexpected binaries or scripts launched by the ClickOnce deployment service.
*   Educate users on the risks associated with clicking suspicious links and installing software from unverified sources, emphasizing that installations may not always require administrator prompts.
