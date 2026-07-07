---
title: Threat Actors Actively Abusing ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce application deployment technology for initial access, stealthy malware execution, and persistence, by exploiting its user-friendly, minimal-interaction deployment process and built-in update mechanism.
date: "2026-07-07T15:13:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - initial-access
  - persistence
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
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'This ease of delivering the payload is tied to a second motive: Threat actors are taking advantage of the general lack of awareness around ClickOnce apps, CrowdStrike observations show.'
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
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce AppRef-ms Persistence via Startup Folder
    description: Detects the creation of a ClickOnce .appref-ms shortcut file in a user's Startup folder, which adversaries abuse for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce AppRef-ms Persistence via Scheduled Task
    description: Detects the creation of a scheduled task that executes a ClickOnce .appref-ms shortcut file, a method abused by threat actors for persistence.
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

Threat actors are actively abusing Microsoft's ClickOnce application deployment technology to achieve initial access, execute malware, and establish persistence. This new abuse vector leverages ClickOnce's user-friendly, minimal-interaction deployment process, where users are often tricked into installing applications via simple clicks on webpages. Attackers exploit the fact that `.application` files can sometimes bypass traditional security scrutiny compared to `.exe` files, and ClickOnce applications do not require elevated privileges for installation, lowering the barrier for attacks against standard user accounts. A key method involves initially convincing users to install a seemingly benign ClickOnce app, then pushing malicious updates to the application's deployment server. When the user launches the application (often via a Start Menu shortcut), the malicious payload is downloaded and executed stealthily within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`. Persistence is further achieved by placing `.appref-ms` shortcut files in the user's Startup folder or by creating scheduled tasks to regularly launch these files, ensuring sustained access and the ability to update malware.

## Attack Chain

1.  Threat actors deliver a malicious link or file, often via phishing, enticing users to initiate a ClickOnce application deployment.
2.  The user clicks the link or `.application` file, triggering the installation of a (potentially benign) ClickOnce application with minimal user interaction and no elevated privileges.
3.  The ClickOnce application creates an `.appref-ms` shortcut file in the user's Start Menu, enabling offline access and triggering updates.
4.  The threat actor either compromises the legitimate ClickOnce application's deployment server or, having convinced the user to install a benign app, replaces the benign application with a malicious update on the deployment server.
5.  For enhanced persistence, the attacker places the `.appref-ms` file in the user's `Startup` folder (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to regularly execute the `.appref-ms` file.
6.  The user (or the persistence mechanism) launches the ClickOnce application via the `.appref-ms` shortcut. The application fetches the malicious update from the compromised deployment server, downloads it, and executes the malicious payload.
7.  The malicious payload executes stealthily within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, establishing command and control (C2).
8.  The attacker uses ClickOnce's built-in updating mechanism to maintain remote access, update malware, and potentially perform lateral movement or data exfiltration.

## Impact

The abuse of ClickOnce technology leads to unauthorized code execution and persistent access on targeted systems. Attackers can bypass common security controls that scrutinize `.exe` files, leveraging the perceived legitimacy of ClickOnce deployments and the stealth offered by executing within trusted Microsoft processes. The lack of elevated privilege requirements enables attackers to target standard user accounts, broadening the victim pool. Successful exploitation results in the compromise of endpoints, potential data exfiltration, establishment of persistent backdoors, and the ability to continuously update malicious capabilities, significantly impacting an organization's security posture and data integrity.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Enable process creation logging, file event logging (specifically for file creation), and scheduled task logging (Event ID 4698) on Windows endpoints to activate the rules above.
*   Implement application whitelisting or strict execution policies that prevent execution of `.appref-ms` files from unusual or untrusted locations.
*   Educate users on the risks associated with clicking links from untrusted sources, particularly those initiating software installations, and the implications of ClickOnce application deployments.
