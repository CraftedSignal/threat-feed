---
title: Threat Actors Weaponize ClickOnce Technology for Initial Access, Execution, and Persistence
slug: 2026-06-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology, specifically targeting the `.application` and `.appref-ms` file types, to achieve stealthy initial access, execute malicious payloads within legitimate Microsoft processes like rundll32.exe and dfsvc.exe, and establish persistence through its built-in update mechanism, effectively bypassing traditional endpoint security controls.
date: "2026-06-20T15:37:33Z"
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Deployment Via rundll32.exe from Remote Source
    description: Detects rundll32.exe loading dfshim.dll to initiate ClickOnce deployment, indicating potential execution of a remote or downloaded .application file. This is a common method for initial execution of malicious ClickOnce payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1218.011
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Service Spawning Suspicious Processes
    description: Detects the dfsvc.exe (ClickOnce Deployment Service) spawning common scripting engines or utilities often used by malware, indicating a malicious payload being executed via the ClickOnce mechanism.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious .appref-ms File Creation in Start Menu
    description: Detects the creation of .appref-ms files in the user's Start Menu by processes other than legitimate ClickOnce components (dfsvc.exe) or web browsers (which trigger dfsvc.exe). This may indicate an attempt to establish persistence by directly planting a malicious ClickOnce shortcut.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Threat actors are increasingly leveraging Microsoft's ClickOnce application deployment technology as a robust vector for delivering malware, achieving initial access, and maintaining persistence on Windows endpoints. This new abuse, highlighted by CrowdStrike, takes advantage of ClickOnce's user-friendly deployment process, which requires minimal user interaction and no administrative privileges, making it highly effective against standard user accounts. Attackers exploit the fact that `.application` and `.appref-ms` files often bypass the scrutiny applied to `.exe` files, allowing malicious payloads to execute within legitimate Microsoft process trees (e.g., `rundll32.exe` and `dfsvc.exe`). By controlling the deployment server, adversaries can push malicious updates to seemingly benign applications, ensuring persistent remote access and the ability to update their malware as needed, including for lateral movement and C2 address changes. This method presents a significant challenge to defenders due to its stealthiness and ability to evade traditional detection mechanisms.

## Attack Chain

1.  **Initial Access**: Threat actors initiate the attack via social engineering, typically through phishing emails or malicious websites, to trick users into clicking a link or button.
2.  **Deployment Trigger**: The user interaction results in the download and subsequent execution (or "running") of a malicious ClickOnce manifest file (`.application`).
3.  **Application Launch**: Windows processes the `.application` file by launching `rundll32.exe` with `dfshim.dll` to handle the ClickOnce deployment.
4.  **Malicious Payload Execution**: `rundll32.exe` (via `dfshim.dll`) or `dfsvc.exe` (the ClickOnce Deployment Service) connects to an attacker-controlled remote server specified in the manifest, downloads application components, and executes a malicious payload within their legitimate process trees.
5.  **Persistence Establishment**: As part of the deployment, a malicious `.appref-ms` shortcut file is dropped into the user's Start Menu directory (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
6.  **Remote Update Mechanism**: The `.appref-ms` file is configured for offline availability and points to the attacker-controlled deployment server, enabling dynamic content delivery.
7.  **Persistent Malicious Execution**: Subsequent launches of the application from the Start Menu via the `.appref-ms` shortcut trigger `dfsvc.exe` to check the attacker-controlled server, download, and execute updated or entirely new malicious components without requiring further user authorization.
8.  **Impact**: This grants adversaries persistent remote access, facilitates command and control updates, and enables further post-exploitation activities such as lateral movement, all while operating under the guise of legitimate system processes.

## Impact

The abuse of ClickOnce technology allows threat actors to achieve highly stealthy and persistent access to victim systems. By operating within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), malicious payloads can bypass many traditional endpoint detection and prevention mechanisms. This method lowers the barrier to entry for attackers as it requires no elevated privileges and minimal user interaction. Successful attacks lead to persistent remote access, enabling data exfiltration, C2 communication, deployment of additional malware, and potential lateral movement across the network, making it difficult to detect and remediate.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Enable Sysmon process creation (Event ID 1) logging to capture `rundll32.exe` and `dfsvc.exe` activity for the `Detect ClickOnce Deployment Via rundll32.exe from Remote Source` and `Detect ClickOnce Service Spawning Suspicious Processes` rules.
*   Configure file event logging (e.g., Sysmon Event ID 11 for file creation) for the `Detect Suspicious .appref-ms File Creation in Start Menu` rule.
*   Educate users about the dangers of running `.application` files from untrusted sources, even if they appear to originate from seemingly legitimate websites or emails.
