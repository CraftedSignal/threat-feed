---
title: New Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology to gain initial access and establish persistence on target systems with minimal user interaction, bypassing traditional security controls and executing within legitimate process trees.
date: "2026-07-07T08:07:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - initial-access
  - defense-evasion
  - windows
  - malware-delivery
vendors:
  - Microsoft
products:
  - .NET Framework
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system. This option significantly simplifies the delivery phase of the kill chain as it bypasses common protection mechanisms such as mailbox filtering systems.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system... Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder...
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening... or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: med
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
    evidence: When opened, the .appref-ms gets the ClickOnce components to fetch available updates from the deployment server, download any potential new components, and run the application. ... All they have to do is push a malicious update into the deployment server...
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious ClickOnce Service Execution
    description: Detects potentially malicious execution chains where dfsvc.exe (Deployment Foundation Services) or rundll32.exe (used by ClickOnce for execution) are spawned by unusual parent processes or with suspicious command-line arguments, potentially indicating malware execution via ClickOnce.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application Persistence via Startup Folder
    description: Detects the creation or modification of .appref-ms files within the user's Startup folder, which can be leveraged by attackers to establish persistence for malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task for ClickOnce Persistence
    description: Detects the creation of scheduled tasks that are configured to execute .appref-ms files, a method used by threat actors to ensure persistent execution of malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - scheduled_task_creation
      - windows
rules_count: 3
---

Generic threat actors are leveraging novel methods to weaponize Microsoft's ClickOnce application deployment technology, as detailed by CrowdStrike. This "new abuse," building on existing attack vectors, allows adversaries to achieve initial access and maintain persistent control over compromised systems. The attack vector is particularly effective due to the user-friendly nature of ClickOnce deployments, which require minimal interaction and often bypass traditional email filtering and executable scrutiny. Attackers can deploy malware via `.application` files, often convincing users to click misleading buttons on web pages. A key feature of this abuse is the ability to leverage ClickOnce's built-in update mechanism to push malicious payloads to previously installed, benign applications, and to establish persistence using `.appref-ms` shortcut files in standard startup locations or via scheduled tasks. The malicious payloads execute stealthily within legitimate Microsoft process trees such as `rundll32.exe` and `dfsvc.exe`, further evading detection.

## Attack Chain

1.  **Initial Access**: Threat actors send phishing emails or direct users to malicious websites containing links to `.application` files or misleading buttons that trigger ClickOnce deployments.
2.  **Execution - User Execution**: The target user clicks on the malicious link or `.application` file, initiating the ClickOnce application deployment.
3.  **Deployment & Malicious Execution**: The ClickOnce client downloads and executes the attacker-controlled application. The malicious payload often executes under legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`.
4.  **Persistence - Shortcut Creation**: A legitimate `.appref-ms` shortcut file for the installed ClickOnce application is dropped into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Persistence - Autostart / Scheduled Task**: To ensure continued execution, the attacker may place the `.appref-ms` file in the Startup folder (`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`) or create a scheduled task to regularly open the `.appref-ms` file.
6.  **Persistence - Update Mechanism**: If the application is configured for offline availability, the attacker can later push malicious updates to the deployment server, and the next time the user launches the application via the `.appref-ms` shortcut, the updated malicious payload is downloaded and executed without further user prompts.
7.  **Command and Control / Impact**: The deployed malware establishes remote access, enabling further compromise, data exfiltration, or other attacker objectives.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common security controls, deploy malware with minimal user interaction, and establish resilient persistence mechanisms. Attackers can gain control over enterprise endpoints, even those with standard user privileges, as ClickOnce does not require administrator rights for installation. The execution of malicious code within legitimate Microsoft processes significantly increases stealth, making detection challenging for traditional security tools. Successful exploitation can lead to prolonged remote access, data breaches, and further lateral movement within the victim's network. While no specific victim counts are given, CrowdStrike indicates observed usage by threat actors, implying widespread potential targeting.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious ClickOnce-related activities.
*   Configure endpoint detection and response (EDR) solutions to monitor `process_creation` events involving `dfsvc.exe` and `rundll32.exe` for unusual parent-child relationships, as outlined in the "Detect Suspicious ClickOnce Service Execution" rule.
*   Ensure `file_event` logging is enabled for the `%AppData%\Microsoft\Windows\Start Menu\Programs\` and `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup` paths to detect the creation or modification of `.appref-ms` files, as highlighted by the "Detect ClickOnce Application Persistence via Startup Folder" rule.
*   Regularly review `scheduled_task_creation` events for tasks configured to execute `.appref-ms` files, as described in the "Detect Scheduled Task for ClickOnce Persistence" rule.
*   Educate users about the risks associated with clicking on unfamiliar links, especially those initiating software installations from untrusted sources, even if they appear to be legitimate system prompts.
