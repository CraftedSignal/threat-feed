---
title: 'New Abuse of ClickOnce Technology: Persistence and Delivery'
slug: 2026-06-clickonce-abuse
description: Threat actors are exploiting the legitimate Microsoft ClickOnce application deployment technology to deliver malware with minimal user interaction, achieve persistence via its built-in update mechanism, and execute payloads within trusted Microsoft process trees, bypassing traditional security controls and maintaining long-term access.
date: "2026-06-20T09:10:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - initial-access
  - malware-delivery
  - clickonce
  - windows
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious Child Process from ClickOnce Service
    description: Detects the ClickOnce Deployment Service (dfsvc.exe) spawning commonly abused system binaries or unsigned executables, indicating potential malware execution via ClickOnce.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Deployment Service Connecting to Uncommon External Hosts
    description: Identifies outbound network connections initiated by dfsvc.exe to external IP addresses or domains that are not typically associated with legitimate Microsoft services or known update servers, potentially indicating C2 communication or malicious update retrieval.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Rundll32.exe Loading from ClickOnce Cache
    description: Detects rundll32.exe, commonly used by ClickOnce, loading a DLL from a user's ClickOnce application cache directory, potentially indicating execution of a malicious payload or update.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Threat actors are increasingly abusing Microsoft's ClickOnce technology as a stealthy and effective method for initial access, malware delivery, and persistence. Observed since June 2026, this technique leverages ClickOnce's user-friendly deployment model, which requires minimal user interaction and no elevated privileges, allowing attackers to target standard user accounts and circumvent common defenses like email filtering. A key advantage for adversaries is ClickOnce's built-in update mechanism; by controlling the deployment server, attackers can push malicious updates to an already installed (potentially benign) application. This grants them a reliable method for maintaining remote access, updating command and control (C2) infrastructure, and facilitating lateral movement, all while operating under the guise of legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`) and UI elements.

## Attack Chain

1.  **Initial Access**: Threat actors convince a user to click a web link or button that initiates the download and installation of a ClickOnce application, often distributed as a `.application` file. This bypasses typical executable scrutiny.
2.  **Initial Execution**: Upon user interaction, the ClickOnce application is deployed and executed, typically by `dfsvc.exe` (ClickOnce Deployment Service) and `rundll32.exe`, which installs the application to a user-specific cache.
3.  **Persistence Setup**: If the ClickOnce application is configured for offline availability, an `.appref-ms` shortcut file is dropped in the Windows Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Attacker Control of Deployment Server**: The threat actor gains control of the server hosting the ClickOnce application, enabling them to modify the application's manifest and package to include malicious components.
5.  **Malicious Update Push**: The attacker pushes a malicious update to the deployment server, which is then made available to installed ClickOnce applications.
6.  **Re-execution and Update**: The next time the user launches the application via the `.appref-ms` shortcut from the Start Menu, the ClickOnce components check for updates, download the malicious changes from the attacker-controlled server, and execute them.
7.  **Payload Execution**: The malicious payload is executed within the legitimate `dfsvc.exe` and `rundll32.exe` process tree, establishing persistence and maintaining remote access (e.g., for C2 communication, data exfiltration, or further malware deployment).

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and execute arbitrary code on targeted systems with high stealth. This vector is particularly dangerous as it circumvents common email and endpoint security protections that scrutinize `exe` files, allowing malicious `.application` files to "fly under the radar." If successful, organizations face remote access, potential data exfiltration, deployment of additional malware (e.g., ransomware, infostealers), and a significant challenge in detection due to the use of legitimate system processes and update mechanisms. The lack of administrator privileges required for installation broadens the attack surface to include standard user accounts across enterprise environments.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related activity.
*   Enable Sysmon process-creation logging to activate the `Detect Suspicious Child Process from ClickOnce Service` and `Detect Rundll32.exe Loading from ClickOnce Cache` rules effectively.
*   Implement robust network traffic monitoring and DNS logging to identify `dfsvc.exe` communicating with unusual or known malicious external destinations, as covered by the `Detect ClickOnce Deployment Service Connecting to Uncommon External Hosts` rule.
*   Educate users on the risks associated with installing software from untrusted sources, even if it appears to be a simple web application launch, emphasizing caution with `.application` and `.appref-ms` files.
