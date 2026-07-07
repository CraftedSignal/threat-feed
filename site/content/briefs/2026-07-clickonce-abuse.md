---
title: Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are exploiting Microsoft's ClickOnce technology to gain initial access, achieve persistence, and execute malicious payloads on Windows systems by leveraging its user-friendly deployment and legitimate update mechanisms, often bypassing traditional defenses.
date: "2026-07-07T18:40:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - initial-access
  - defense-evasion
  - windows
  - social-engineering
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
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
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of a ClickOnce .appref-ms shortcut file within a user's Startup folder, which can be used by threat actors for persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce technology to facilitate initial access, execute malware, and establish persistence on target systems. This technique, highlighted by CrowdStrike, allows adversaries to bypass traditional security controls like mailbox filters by leveraging the inherent trust and minimal user interaction required for ClickOnce application deployment. Attackers entice users to click on malicious links or `.application` files, which then trigger the installation and execution of malware via legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. A significant factor contributing to its effectiveness is the general lack of awareness regarding ClickOnce applications among users and security teams, enabling malicious payloads to "fly under the radar" compared to scrutinized executable files. Furthermore, ClickOnce applications do not require elevated privileges for deployment, expanding the attack surface to standard user accounts. This abuse provides threat actors with a robust method for maintaining remote access and updating their malware through the technology's built-in update mechanism, posing a significant challenge for defenders.

## Attack Chain

1.  **Initial Access**: A user is socially engineered via phishing (e.g., email, malicious website) to click a link or download and open a malicious `.application` file.
2.  **Execution Trigger**: Upon clicking the link or opening the `.application` file, the ClickOnce deployment process is initiated on the user's Windows system.
3.  **Defense Evasion & Execution**: The ClickOnce application is launched via legitimate Windows processes such as `dfsvc.exe` and `rundll32.exe`, executing the embedded malicious payload with minimal user interaction and leveraging trusted system binaries to evade detection.
4.  **Persistence (Shortcut Creation)**: The ClickOnce application drops an `.appref-ms` shortcut file in the user's Start Menu directory (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) to provide an easy launch point for the application, enabling offline use.
5.  **Persistence (Malicious Updates)**: The adversary, who controls the ClickOnce deployment server, pushes malicious updates to the deployed application. When the user subsequently launches the application via the `.appref-ms` shortcut, the malicious update is silently downloaded and executed.
6.  **Persistence (Autostart)**: To ensure continued execution, the adversary places the `.appref-ms` file in a system autostart location such as the Startup folder or creates a scheduled task to launch the ClickOnce application automatically upon system boot or at regular intervals.
7.  **Command and Control / Impact**: The malicious ClickOnce application establishes command-and-control (C2) communication, enabling remote access, facilitating data exfiltration, or performing further malicious actions like lateral movement or ransomware deployment.

## Impact

The abuse of ClickOnce technology allows adversaries to achieve deep compromises with significant impact. If successful, this attack vector results in the unhindered execution of malicious code, bypassing email security and endpoint protection mechanisms. The ability to deploy without administrative privileges means all Windows endpoints are vulnerable. Furthermore, the built-in update mechanism grants attackers a persistent foothold and reliable means to modify their malware, facilitating long-term remote access, data exfiltration, and the ability to pivot to other systems. This can lead to complete network compromise, sensitive data breaches, and significant operational disruption.

## Recommendation

*   Deploy the Sigma rule provided in this brief to detect the creation of `.appref-ms` files in the Windows Startup folder, indicating potential persistence.
*   Enable comprehensive logging for file creation events (e.g., Sysmon Event ID 11) to capture the creation of `.appref-ms` files, especially in unusual or sensitive directories.
*   Implement user awareness training focusing on the risks associated with clicking suspicious links that initiate software installations, specifically addressing prompts related to ClickOnce applications.
*   Monitor for abnormal process execution patterns involving `dfsvc.exe` and `rundll32.exe`, particularly when they are invoked from unexpected parent processes or with unusual command-line arguments that deviate from legitimate ClickOnce deployment behavior.
