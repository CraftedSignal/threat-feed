---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology for initial access, execution, and persistence, exploiting its user-friendly deployment and built-in update mechanism to bypass traditional security controls and maintain remote access on Windows systems.
date: "2026-07-04T03:17:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - defense-evasion
  - initial-access
  - execution
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
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system...clicking a webpage button can trigger software installation
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening... or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism... whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms file within a user's Startup folder, a common persistence mechanism for malicious ClickOnce applications.
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

Threat actors are leveraging malicious ClickOnce applications to bypass traditional security defenses, gain initial access, execute payloads, and establish persistence on target systems. This abuse, highlighted by CrowdStrike, takes advantage of ClickOnce's minimal user interaction requirement for deployment, which often flies under the radar of security tools that typically scrutinize `.exe` files. Malicious ClickOnce applications can be deployed via web links or `.application` files, executing within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe` to increase stealth. The built-in updating mechanism of ClickOnce is then co-opted to maintain remote access and update malware, enabling attackers to change command and control (C2) addresses or facilitate lateral movement. Persistence is further cemented by strategically placing `.appref-ms` files in common autostart locations such as the Windows Startup folder or by creating scheduled tasks to re-launch the malicious application.

## Attack Chain

1.  **Initial Access:** Threat actors convince a user to click a malicious web link or open a malicious `.application` file delivered via email, which initiates the ClickOnce deployment process, bypassing mailbox filters and user scrutiny.
2.  **Execution & Installation:** The ClickOnce application is installed on the system, often without requiring elevated privileges, as any standard user can install a ClickOnce app.
3.  **Defense Evasion & Execution:** The malicious payload within the ClickOnce application executes within legitimate Microsoft process trees, specifically through `rundll32.exe` and `dfsvc.exe`, increasing stealth and evading detection.
4.  **Persistence (Startup Folder):** To maintain access, the attacker places a malicious `.appref-ms` file (a shortcut to the ClickOnce application) into the user's Startup folder (e.g., `%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).
5.  **Persistence (Scheduled Task):** Alternatively or additionally, the attacker creates a scheduled task that automates the opening of the `.appref-ms` file, ensuring the application runs at specific intervals or system events.
6.  **Command and Control / Updates:** Leveraging ClickOnce's built-in update mechanism, the attacker pushes malicious updates to the installed application from their controlled deployment server whenever the user launches the application, even from the Start Menu.
7.  **Impact:** These updates facilitate changes to C2 infrastructure, allow the deployment of new malicious modules, enable lateral movement within the network, or facilitate other post-exploitation activities, maintaining long-term remote access.

## Impact

The abuse of ClickOnce technology leads to successful initial access, execution, and persistent presence for threat actors on compromised systems. This method allows malware to bypass common protection mechanisms like email filters and security tool scrutiny, as the deployment often appears legitimate to both users and some security products. Attackers gain a reliable method for maintaining remote access, updating their malware payloads, and enabling further malicious activities such as changing C2 addresses or facilitating lateral movement. While the brief does not specify victim counts or targeted sectors, the inherent stealth and persistence mechanisms provided by ClickOnce make it a potent vector for widespread compromise across various enterprise environments.

## Recommendation

*   Deploy the Sigma rule "ClickOnce .appref-ms Persistence via Startup Folder" to detect malicious persistence attempts.
*   Monitor for process creation events (`process_creation` logs) where `dfsvc.exe` or `rundll32.exe` are observed communicating externally to unusual or suspicious IP addresses or domains.
*   Ensure robust web and email gateway filtering (`network_connection` logs, `webserver` logs) that can identify and block `.application` files or links leading to ClickOnce deployments from untrusted sources.
*   Implement application whitelisting (using `process_creation` and `file_event` logs) to restrict the execution of ClickOnce applications to only approved and signed sources, reducing the attack surface.
*   Educate users on the risks associated with unsolicited ClickOnce application installations and suspicious web links, leveraging security awareness training programs.
