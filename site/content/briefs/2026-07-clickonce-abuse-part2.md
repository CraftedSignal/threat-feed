---
title: Threat Actors Weaponizing ClickOnce Technology for Initial Access, Persistence, and Updates
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology to achieve initial access, execution, and persistence by leveraging its user-friendly deployment, which bypasses traditional security controls and executes malicious payloads within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, further enabling persistent command and control through its built-in update mechanism and scheduled tasks.
date: "2026-07-07T07:04:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - defense-evasion
  - initial-access
  - microsoft-windows
  - malware
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
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
    evidence: '...or creating a scheduled task to process the file regularly, they can ensure persist[ence].'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of .appref-ms files in a user's Startup folder, indicating ClickOnce application persistence.
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
    description: Detects the creation of a scheduled task that executes a .appref-ms file, a known method for ClickOnce persistence.
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

CrowdStrike has observed threat actors exploiting Microsoft's ClickOnce technology, primarily for initial access, execution, and persistence. This abuse, detailed in Part 2 of their analysis published on June 18, 2026, capitalizes on ClickOnce's minimal user interaction requirement for application deployment, allowing payloads to circumvent common security defenses like mailbox filters. Attackers leverage the legitimacy of ClickOnce processes, such as `rundll32.exe` and `dfsvc.exe`, to execute malicious code stealthily. A significant new abuse involves weaponizing the ClickOnce update mechanism, enabling attackers who either compromise legitimate application servers or initially trick users into installing a benign app, to push malicious updates later. This allows for maintaining remote access, updating malware, changing command and control (C2) infrastructure, and facilitating lateral movement without further user interaction. Furthermore, attackers establish persistence by placing `.appref-ms` files in common autostart locations or via scheduled tasks.

## Attack Chain

1.  **Initial Access:** Threat actors convince targets to click a malicious link on a webpage or execute a disguised `.application` file delivered via phishing, leveraging the minimal interaction required for ClickOnce deployment.
2.  **Application Deployment:** The user's action triggers the ClickOnce deployment process, which, if configured for offline availability, drops an application reference file (`.appref-ms`) into the user's Start Menu (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
3.  **Persistence (Startup Folder):** Attackers establish persistence by placing the newly deployed `.appref-ms` file into the user's Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), ensuring execution upon logon.
4.  **Persistence (Scheduled Task):** Alternatively or additionally, attackers create a scheduled task (e.g., using `schtasks.exe`) to regularly execute the `.appref-ms` file, ensuring persistent and automated re-execution of the application.
5.  **Malicious Update Delivery:** When the `.appref-ms` file is launched (either via the Start Menu, Startup folder, or scheduled task), the ClickOnce components automatically fetch available updates from the deployment server. If the attacker controls this server or initially deployed a benign application that was later compromised, a malicious update is pushed.
6.  **Payload Execution:** The updated malicious application executes its payload, often within legitimate Microsoft process trees like `rundll32.exe` and `dfsvc.exe`, leveraging their trusted nature to evade detection.
7.  **Command and Control & Impact:** The now-malicious application establishes remote access, enables command and control (C2) communication (e.g., to change C2 addresses), updates additional malware components, and facilitates lateral movement within the network, ultimately leading to data exfiltration, further system compromise, or other adversarial objectives.

## Impact

The abuse of ClickOnce technology allows attackers to bypass common security controls, install malware without elevated privileges, and maintain persistent access to compromised systems. Organizations where this attack succeeds face significant risks including initial network compromise, undetected malware execution, and long-term remote access for threat actors. This can lead to sensitive data exfiltration, deployment of ransomware, or further lateral movement into critical infrastructure. The lack of user awareness regarding ClickOnce deployment mechanisms further amplifies the attack's effectiveness, making enterprises vulnerable to persistent, stealthy threats.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Monitor `file_event` logs for the creation or modification of `.appref-ms` files within user Startup folders, as described in the "Detect ClickOnce Persistence via Startup Folder" rule.
*   Monitor `process_creation` logs for `schtasks.exe` command-line arguments that create tasks executing `.appref-ms` files, as highlighted by the "Detect ClickOnce Persistence via Scheduled Task" rule.
*   Educate users on the risks associated with clicking suspicious links or downloading `.application` files, even those appearing to be legitimate software installers.
