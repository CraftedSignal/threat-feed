---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse
description: Threat actors are abusing Microsoft's ClickOnce technology to simplify the delivery and execution of malware, and to establish persistence on target systems, leveraging its user-friendliness, bypass of traditional security tools, lack of privilege requirements, and built-in update mechanisms to push malicious updates or achieve persistence by manipulating .appref-ms files and scheduled tasks.
date: "2026-07-07T11:44:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce applications
  - .application files
  - .appref-ms files
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
    evidence: clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first. This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: or creating a scheduled task to process the file regularly, they can ensure persist
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
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation of .appref-ms files in a user's Startup folder, which is a common persistence mechanism for abused ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task Creation
    description: Detects the creation of a scheduled task that explicitly references and executes an .appref-ms file, indicating potential ClickOnce persistence.
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

CrowdStrike has identified a new method of abuse targeting Microsoft's ClickOnce technology, enabling threat actors to simplify malware delivery and persistence without requiring elevated privileges. This attack vector leverages the user-friendly nature of ClickOnce applications, which often bypass traditional security controls like email filters due to their `.application` file extension, typically triggering deployment with minimal user interaction. Adversaries exploit the general lack of awareness regarding ClickOnce, allowing malicious payloads to be installed by simply clicking a deceptive webpage button. A key aspect of this abuse is the manipulation of the `.appref-ms` file, which can be placed in the Windows Startup folder or invoked by scheduled tasks to establish persistence. Furthermore, the built-in update mechanism of ClickOnce applications can be co-opted to push malicious updates, enabling long-term remote access and control within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. This poses a significant risk to organizations as it allows for stealthy and persistent compromises.

## Attack Chain

1.  **Initial Access**: A user is tricked into clicking a malicious link (e.g., in a phishing email) or opening a weaponized `.application` file.
2.  **Execution**: The user interaction triggers the ClickOnce deployment mechanism, which uses legitimate Windows processes like `dfsvc.exe` and `rundll32.exe` to execute the attacker's payload.
3.  **Malware Deployment**: The malicious ClickOnce application is installed on the victim's system, often without requiring administrative privileges, bypassing standard installation prompts.
4.  **Persistence Establishment (Startup Folder)**: The attacker places a shortcut to the malicious application, typically an `.appref-ms` file, into the user's `Start Menu\Programs\Startup` folder.
5.  **Persistence Establishment (Scheduled Task)**: Alternatively, the attacker creates a Scheduled Task configured to regularly launch the `.appref-ms` file, ensuring repeated execution of the malicious application.
6.  **Command and Control via Updates**: The built-in ClickOnce update mechanism is utilized, allowing the attacker (who controls the deployment server) to push subsequent malicious updates to change C2 infrastructure, exfiltrate data, or deliver additional malware.
7.  **Impact**: The malicious application maintains persistent execution within legitimate Microsoft process trees, enabling stealthy long-term access, lateral movement, and data exfiltration.

## Impact

The abuse of ClickOnce applications has a broad impact, primarily due to its ability to bypass traditional security defenses and achieve persistent access with minimal user interaction and no administrative privileges. This method of delivery allows attackers to target a wide range of standard user accounts across organizations. If successful, it leads to the stealthy installation and execution of malware, as it operates within legitimate Microsoft processes, making detection difficult. The built-in update mechanism ensures attackers can modify their payload over time, adapting to defenses or escalating privileges, ultimately leading to sustained compromise, data exfiltration, and potential disruption of operations across affected systems.

## Recommendation

*   Deploy the provided Sigma rules to detect suspicious ClickOnce persistence mechanisms and tune for your environment.
*   Enable Sysmon file creation events (Event ID 11) and process creation events (Event ID 1) to activate the rules above.
*   Educate users about the risks associated with clicking on untrusted links and opening `.application` files, even from seemingly legitimate sources.
*   Monitor process execution involving `dfsvc.exe` and `rundll32.exe` for unusual parent processes or network connections to external, suspicious domains.
