---
title: Threat Actors Abusing Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are weaponizing Microsoft's ClickOnce technology, detailed in a June 2026 CrowdStrike report, to achieve initial access and persistence by bypassing traditional security controls and leveraging built-in update mechanisms to deploy and update malware via legitimate Windows processes.
date: "2026-07-07T16:20:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - windows
  - microsoft-technology
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce applications
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder... they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: While .exe files are heavily scrutinized and controlled in most environments, .application files can sometimes fly under the radar of security tools, creating an opportunity for threat actors to slip through traditional defenses.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce Abuse - Suspicious Processes Launched by dfsvc.exe or rundll32.exe
    description: Detects suspicious executables being launched by dfsvc.exe or rundll32.exe, indicating potential ClickOnce abuse to execute malware within legitimate process trees.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
      - T1204.001
    data_sources:
      - process_creation
      - windows
  - title: ClickOnce Abuse - appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of .appref-ms files within user Startup folders, indicating potential ClickOnce abuse for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: ClickOnce Abuse - Scheduled Task for appref-ms Execution
    description: Detects the creation of scheduled tasks designed to execute .appref-ms files, a known persistence mechanism for ClickOnce abuse.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology to gain initial access, establish persistence, and update malware on victim systems, as detailed in a June 2026 CrowdStrike report. This attack vector leverages ClickOnce's user-friendly deployment, which often bypasses traditional security controls like mailbox filters due to its reliance on `.application` files or simple web clicks. Attackers are abusing the general lack of awareness around ClickOnce, often tricking users into installing applications without needing administrative privileges. A key abuse involves using `.appref-ms` files, which are shortcuts to offline ClickOnce apps, to facilitate stealthy updates and persistence. By dropping a malicious `.appref-ms` file in the Startup folder or scheduling its execution, attackers can ensure their payloads are run through legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, making detection challenging. This method allows for reliable malware updates, lateral movement, and C2 modifications, turning a legitimate deployment mechanism into a powerful tool for maintaining long-term access.

## Attack Chain

1.  **Initial Access**: A user is lured into clicking a malicious link or opening a weaponized `.application` file, often via a phishing campaign, to initiate the ClickOnce deployment.
2.  **Deployment**: The ClickOnce application deploys, requiring minimal user interaction and bypassing the need for administrative privileges, exploiting user's lack of awareness regarding `.application` files.
3.  **Execution and Masquerading**: The malicious payload embedded within the ClickOnce app executes, operating under the context of legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`.
4.  **Persistence (Update Mechanism)**: If the ClickOnce application is configured for offline availability, an `.appref-ms` shortcut file is dropped in the user's Start Menu programs folder.
5.  **Persistence (Startup/Scheduled Task)**: The attacker leverages the `.appref-ms` file by placing it in the Windows Startup folder (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`) or creating a scheduled task to execute it regularly.
6.  **Command and Control / Updates**: The ClickOnce application's built-in update mechanism is exploited to fetch and download new malicious components from an attacker-controlled deployment server without user intervention.
7.  **Post-Exploitation**: The updated malware establishes command and control, facilitates lateral movement within the network, changes C2 addresses, exfiltrates data, or performs other attacker objectives.

## Impact

Successful exploitation of ClickOnce technology allows threat actors to establish persistent footholds on target systems, often without requiring administrative privileges, which significantly broadens the attack surface. The abuse bypasses common email filtering systems and other traditional endpoint security mechanisms, leading to stealthy initial access and execution. Once deployed, attackers can reliably update their malware, enabling them to adapt their tools and tactics, maintain remote access, pivot to lateral movement, or conduct data exfiltration. The use of legitimate Microsoft processes further complicates detection, allowing malicious activity to blend with benign system operations, ultimately increasing the dwell time and potential for significant organizational damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related activity.
*   Enable Sysmon process-creation logging to activate the rule `ClickOnce Abuse - Suspicious Processes Launched by dfsvc.exe or rundll32.exe`.
*   Ensure file event logging is configured to detect creation of `.appref-ms` files in critical locations to activate the rule `ClickOnce Abuse - appref-ms Persistence in Startup Folder`.
*   Implement scheduled task creation logging via process monitoring (`schtasks.exe`) to activate the rule `ClickOnce Abuse - Scheduled Task for appref-ms`.
*   Educate users on the risks associated with clicking on unknown links or opening `.application` files from untrusted sources, even if they appear to initiate a legitimate software installation process.
