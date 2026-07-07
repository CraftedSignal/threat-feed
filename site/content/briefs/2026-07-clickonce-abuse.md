---
title: New Abuse of ClickOnce Technology for Initial Access, Persistence, and C2
slug: 2026-07-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce deployment technology to deliver malware, gain initial access, establish persistence through built-in update mechanisms and startup folders, and maintain command and control, leveraging its user-friendly deployment, lack of scrutiny, and execution within legitimate processes to bypass traditional security defenses.
date: "2026-07-07T19:25:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - execution
  - defense-evasion
  - initial-access
vendors:
  - Microsoft
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of ClickOnce application reference files (.appref-ms) within a user's Startup folder, a common technique for persistence. This rule leverages file event logs.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect dfsvc.exe Spawning Unusual Child Processes
    description: Detects the ClickOnce Deployment Framework Service (dfsvc.exe) spawning child processes that are not typical for legitimate ClickOnce operations, indicating potential malware execution.
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
rules_count: 2
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to distribute malware and establish a foothold in victim environments. This abuse is driven by ClickOnce's minimal user interaction requirement for deployment, often bypassing email filters and user scrutiny that typically flag executable files. The attack vector leverages the general lack of awareness surrounding `.application` and `.appref-ms` files, which often go undetected by security tools. Furthermore, ClickOnce applications do not require elevated privileges for installation, enabling threat actors to target standard user accounts. A key feature exploited is the built-in update mechanism, which allows adversaries to continuously update their malware and maintain remote access by dropping `.appref-ms` files in common persistence locations like the Start Menu. The malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, lending an air of legitimacy to the execution and complicating detection. This ongoing trend highlights a critical blind spot for many organizations.

## Attack Chain

1.  **Initial Access**: Threat actors send spearphishing emails containing malicious links or attachments (e.g., `.application` files) designed to initiate a ClickOnce application installation. Users are lured into clicking misleading buttons on webpages or opening seemingly benign files.
2.  **Execution**: Upon user interaction, the ClickOnce application is downloaded and executed, often leveraging legitimate Microsoft processes like `dfsvc.exe` (Deployment Framework Service) to deploy and run the embedded malicious payload.
3.  **Persistence (Shortcut/Autostart)**: To ensure continued access, the attacker places a `.appref-ms` file (a ClickOnce application shortcut) in the user's Startup folder (`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to launch it regularly.
4.  **Defense Evasion (Process Masquerading)**: The malware executes within the context of legitimate Microsoft process trees (e.g., `rundll32.exe` or `dfsvc.exe` spawning the malicious component), making it harder for security tools and analysts to differentiate malicious activity from normal system operations.
5.  **Command and Control (Update Mechanism)**: The attacker leverages the ClickOnce application's built-in update mechanism. When the user launches the persistent `.appref-ms` shortcut, the application checks for updates from the attacker-controlled server, fetching and executing new malicious components or updated C2 instructions.
6.  **Impact**: Through the established persistence and C2, the attacker gains remote access to the victim's system, allowing for further compromise, data exfiltration, deployment of additional malware, or other post-exploitation activities.

## Impact

The abuse of ClickOnce technology leads to successful malware execution and persistent access on compromised systems. This method often bypasses conventional security controls, enabling attackers to gain initial access without requiring administrator privileges, thus expanding the attack surface to include all standard user accounts. If successful, organizations face significant risks including data breaches, ransomware deployment, network lateral movement, and long-term undetected presence on their endpoints. The stealth provided by execution within legitimate Microsoft processes further complicates incident response and containment efforts, potentially leading to widespread compromise before detection. The inherent trust in ClickOnce's update mechanism allows attackers to maintain ongoing command and control, effectively turning a legitimate deployment feature into a robust C2 channel.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Enable Sysmon file creation logging to activate the `Detect ClickOnce .appref-ms Persistence` rule.
*   Enable Sysmon process-creation logging to activate the `Detect dfsvc.exe Spawning Unusual Child Processes` rule.
*   Implement application whitelisting solutions to restrict execution of `.application` and `.appref-ms` files, especially from untrusted sources or unusual user directories.
*   Educate users about the dangers of unsolicited ClickOnce application installations, particularly those originating from unknown email senders or suspicious websites, referencing the general technique of spearphishing.
