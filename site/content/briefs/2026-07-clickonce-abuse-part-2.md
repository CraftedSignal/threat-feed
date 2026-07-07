---
title: New Abuse of Microsoft ClickOnce Technology for Persistent Malware Execution
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are exploiting Microsoft's ClickOnce technology for initial access, execution, and persistence, leveraging its user-friendly deployment process to bypass security controls and run malicious payloads within legitimate Microsoft processes, maintaining remote access through the built-in update mechanism or by placing `.appref-ms` files in startup locations.
date: "2026-07-04T09:24:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - persistence
  - initial-access
  - defense-evasion
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
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: ""
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: ""
    evidence: creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation of an .appref-ms file in the Windows Startup folder, a known technique for ClickOnce persistence.
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
    description: Detects the creation of a scheduled task that executes a ClickOnce .appref-ms file, indicating potential persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce technology, a legitimate application deployment framework, to achieve initial access, execute malicious payloads, and maintain persistence on target systems. This abuse, highlighted by CrowdStrike, takes advantage of ClickOnce's minimal user interaction requirement for software installation, often bypassing traditional security defenses like email filters and antivirus checks that might scrutinize `.exe` files more closely than `.application` files. Attackers exploit the general lack of user and security team awareness around ClickOnce to deliver malware without requiring elevated privileges. Furthermore, the technology's built-in update mechanism allows adversaries to push new malicious payloads to already installed applications, enabling reliable remote access and command and control updates. Malicious code executes within trusted Microsoft process trees, specifically `rundll32.exe` and `dfsvc.exe`, enhancing stealth and evasion. This technique presents a significant challenge for defenders who need to monitor for unusual ClickOnce activity.

## Attack Chain

1.  **Initial Access via Social Engineering:** The attacker sends a phishing email or hosts a malicious webpage containing a link or `.application` file designed to deploy a ClickOnce application.
2.  **User Execution:** The user, convinced by social engineering tactics, clicks the malicious link or `.application` file, initiating the ClickOnce deployment process.
3.  **Malicious Payload Execution:** The ClickOnce application, containing a hidden malicious payload, deploys and executes on the system without requiring administrative privileges, running within legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`.
4.  **Persistence through Update Mechanism:** The attacker compromises or controls the ClickOnce deployment server and pushes a malicious update. The next time the user launches the installed ClickOnce application via its `.appref-ms` shortcut, the malicious update is silently downloaded and executed.
5.  **Persistence via Startup Folder:** The attacker strategically places the `.appref-ms` file of the deployed malicious ClickOnce application into the user's Windows Startup folder (`%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), ensuring execution upon user logon.
6.  **Persistence via Scheduled Task:** The attacker creates a scheduled task that automatically launches the `.appref-ms` file of the malicious ClickOnce application at predetermined intervals or conditions, maintaining persistent access.
7.  **Command and Control (C2) / Lateral Movement:** The persistently executing malware establishes covert command and control communication with attacker infrastructure, enabling further actions such as lateral movement, data exfiltration, or delivery of additional malicious tools.
8.  **Impact:** The attacker achieves their final objective, which may include data theft, ransomware deployment, or long-term access to the compromised network.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common security controls, establish stealthy persistence, and execute arbitrary code on targeted systems without requiring administrative privileges. This can lead to significant data breaches, ransomware infections, and extended periods of undetected remote access, as the malicious activity often blends in with legitimate system processes (`rundll32.exe`, `dfsvc.exe`). Organizations across all sectors are vulnerable, with the user-friendly nature of ClickOnce deployment acting as a highly effective social engineering vector. If successful, these attacks result in compromised endpoints, potential network-wide breaches, and loss of sensitive information.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable Sysmon file creation logging (`event_id: 11`) to activate the `Detect ClickOnce Persistence via Startup Folder` rule.
*   Enable Sysmon process-creation logging (`event_id: 1`) to activate the `Detect ClickOnce Persistence via Scheduled Task` rule.
*   Educate users on the risks associated with clicking links or opening `.application` files from untrusted or unexpected sources, regardless of whether they appear to be legitimate software installers.
*   Implement application whitelisting or strict software deployment policies to limit unauthorized ClickOnce application installations.
