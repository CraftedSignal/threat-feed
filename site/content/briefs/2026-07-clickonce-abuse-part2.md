---
title: New Abuse of ClickOnce Technology for Stealthy Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively weaponizing Microsoft's ClickOnce technology to achieve initial access, stealthy execution within legitimate processes, and persistent remote access by leveraging its minimal user interaction requirements and built-in updating mechanism, bypassing traditional defenses.
date: "2026-07-07T20:22:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - initial-access
  - persistence
  - malware-delivery
  - windows
vendors:
  - Microsoft
products:
  - Microsoft ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: users rarely realize that clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce AppRef-Ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce '.appref-ms' file in common Windows startup folders, a known technique for achieving persistence.
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

Threat actors are increasingly exploiting Microsoft's ClickOnce application deployment technology to deliver malware and establish persistence on target systems. This abuse, observed by CrowdStrike, takes advantage of ClickOnce's user-friendly deployment, which often requires minimal user interaction to install applications, effectively bypassing traditional security scrutiny typically applied to `.exe` files. Adversaries leverage this by luring users into clicking deceptive links or `.application` files. A significant aspect of this technique is the ability for attackers to push malicious updates to an initially benign-looking ClickOnce application, ensuring the payload executes discreetly within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`. Furthermore, the `.appref-ms` shortcut files created during installation can be manipulated for persistence, allowing actors to maintain remote access and update their C2 infrastructure.

## Attack Chain

1.  Threat actor sends a deceptive link, often via phishing email or malicious website, designed to initiate a Microsoft ClickOnce application deployment when clicked.
2.  The victim clicks the malicious link or a `.application` file. The ClickOnce deployment service (`dfsvc.exe`) initiates the download and installation of the (potentially initially benign or disguised) ClickOnce application.
3.  During installation, an `.appref-ms` shortcut file is dropped in the user's Start Menu (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) for offline availability.
4.  The application deploys without requiring elevated privileges, executing within legitimate Microsoft processes such as `dfsvc.exe`, potentially launching `rundll32.exe`, thus evading typical `.exe` scrutiny.
5.  The attacker, controlling the ClickOnce deployment server, pushes a malicious update for the previously installed application.
6.  When the user next launches the application via the `.appref-ms` shortcut, the ClickOnce update mechanism automatically downloads and executes the malicious payload from the controlled server, typically without additional user prompts.
7.  To ensure continuous persistence, the attacker places the `.appref-ms` file in the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to regularly execute it.
8.  The malicious payload gains execution within a legitimate Microsoft process tree, enabling actions such as remote access, data exfiltration, or further compromise of the system.

## Impact

The abuse of ClickOnce technology allows threat actors to circumvent common security controls and deliver malware with high stealth. This leads to successful initial access, persistent presence on compromised endpoints, and the ability to update malicious payloads or C2 addresses without detection. Organizations may experience data breaches, ransomware infections, or other forms of system compromise, as security tools often overlook `.application` files and legitimate Windows processes. The widespread unawareness of ClickOnce's security implications among users further exacerbates the risk, making it an effective vector for targeting standard user accounts across various enterprise environments.

## Recommendation

*   Deploy the Sigma rule below to detect suspicious `.appref-ms` file persistence, and investigate all alerts.
*   Educate users about the risks of clicking on unexpected links or files, particularly those initiating software installations, and emphasize caution around `.application` file types.
*   Enable Sysmon file event logging (`FileCreate`, `FileCreateStreamHash`, `FileRename`, `FileDelete`) for `.appref-ms` files to activate the detection rule provided.
*   Monitor process creation events for `dfsvc.exe` and its child processes, looking for unusual network connections or subsequent malicious activity.
