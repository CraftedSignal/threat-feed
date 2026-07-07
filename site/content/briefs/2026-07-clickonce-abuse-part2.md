---
title: New Abuse of ClickOnce Technology for Stealthy Persistence and Execution
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are abusing Microsoft's ClickOnce technology for initial access, execution, persistence, and defense evasion by leveraging its user-friendly deployment, ability to bypass traditional security defenses, lack of privilege requirements, and legitimate process execution, enabling covert malware delivery and updates.
date: "2026-07-04T07:04:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - initial-access
  - defense-evasion
  - windows
  - living-off-the-land
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
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
iocs:
  - type: file_name
    value: .application
  - type: file_name
    value: .appref-ms
  - type: file_path
    value: '%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\'
ioc_counts:
  file_name: 2
  file_path: 1
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of a ClickOnce application reference file (.appref-ms) within the Windows Startup folder, a known technique for persistence by threat actors abusing ClickOnce technology.
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

Threat actors are actively leveraging Microsoft's ClickOnce technology, a legitimate application deployment framework, as a potent vector for initial access, persistence, and defense evasion. This new abuse, identified by CrowdStrike, allows adversaries to deploy malware with minimal user interaction, often bypassing traditional security controls like email filters due to the perceived legitimacy of `.application` files. Attackers exploit the fact that ClickOnce applications do not require elevated privileges for installation and can run within trusted Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. Furthermore, the built-in update mechanism of ClickOnce enables adversaries to maintain persistent access and update their malicious payloads or C2 infrastructure. The campaign targets a wide range of organizations, taking advantage of a general lack of awareness regarding the security implications of ClickOnce apps, making it a stealthy and effective attack method.

## Attack Chain

1.  Threat actors convince a target user to click a malicious link or open a seemingly benign `.application` file to initiate deployment.
2.  The user interaction triggers the deployment of a ClickOnce application from an attacker-controlled server, often bypassing traditional security scrutiny.
3.  The ClickOnce application executes, running initial malicious payloads within legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe` to evade detection.
4.  To establish persistence, attackers place the ClickOnce application's shortcut file (`.appref-ms`) into the Windows Startup folder (e.g., `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`) or create a scheduled task to launch it.
5.  Upon subsequent system startup or scheduled execution, the `.appref-ms` file initiates an update check with the attacker's server without additional user prompts.
6.  The attacker leverages the legitimate ClickOnce update mechanism to deliver additional malicious components, update malware, or modify command and control (C2) infrastructure.
7.  This allows adversaries to maintain remote access, potentially escalate privileges through further stages, and exfiltrate data, achieving their final objectives.

## Impact

This abuse allows threat actors to establish persistent and stealthy access within victim environments. Because ClickOnce applications do not require administrative privileges, standard user accounts across an organization are vulnerable, significantly broadening the attack surface. Successful exploitation leads to initial compromise, persistence through legitimate OS features, and covert command and control. The attackers can update their malware at will, enabling dynamic changes to their objectives, including data exfiltration, lateral movement, or ransomware deployment, without requiring repeated user interaction or re-triggering security alerts typically associated with new malware deployments.

## Recommendation

*   Enable file event logging (e.g., Sysmon Event ID 11) to detect the creation of `.appref-ms` files, particularly in sensitive persistence locations such as the Startup folder mentioned in this brief.
*   Deploy the Sigma rule "Detect ClickOnce .appref-ms Persistence via Startup Folder" to your SIEM and tune for your environment.
*   Implement application whitelisting or strict execution policies to restrict the execution of `.application` files and other executable types not explicitly approved, as described in the brief.
*   Educate users about the risks associated with clicking on links from untrusted sources, even if they appear to initiate benign application installations.
