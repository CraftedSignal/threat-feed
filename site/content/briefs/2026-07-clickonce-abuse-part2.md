---
title: Threat Actors Abuse ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively leveraging Microsoft's ClickOnce technology, specifically the `dfsvc.exe` and `appref-ms` mechanisms, to deliver malware, evade detection, establish persistence, and maintain remote access without requiring elevated privileges.
date: "2026-07-04T07:22:48Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - windows
  - execution
  - initial-access
vendors:
  - Microsoft
products:
  - ClickOnce Application Deployment
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
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
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
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect Suspicious ClickOnce Deployment Service Child Processes
    description: Detects the ClickOnce Deployment Service (dfsvc.exe) spawning known malicious or uncommon child processes, which can indicate malicious ClickOnce application execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application Reference File Creation
    description: Detects the creation of '.appref-ms' files, which are used for ClickOnce persistence and launching applications, especially when created by non-standard processes or in unusual locations.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Threat actors are increasingly exploiting Microsoft's ClickOnce application deployment technology to bypass traditional security defenses and maintain persistent access to target systems. This abuse, highlighted by CrowdStrike, takes advantage of ClickOnce's user-friendly deployment, which requires minimal user interaction, and a general lack of awareness regarding `.application` and `.appref-ms` files. Unlike `.exe` files, ClickOnce components often fly under the radar of security tools. Attackers can deliver malicious payloads that execute within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, increasing stealth. Furthermore, the built-in update mechanism of ClickOnce applications allows adversaries to push malicious updates to already installed benign applications, establishing a robust persistence and command-and-control channel without requiring administrator privileges.

## Attack Chain

1.  **Initial Access / Delivery:** Threat actor crafts a malicious ClickOnce application and convinces the target to click on a misleading web button or open a malicious `.application` file.
2.  **Execution (ClickOnce Deployment):** User interaction triggers the ClickOnce Deployment Service (`dfsvc.exe`), which downloads and installs the malicious application without requiring administrator privileges.
3.  **Malware Execution:** The malicious ClickOnce application executes, often spawning the payload via `rundll32.exe` within legitimate Microsoft process trees, enhancing stealth.
4.  **Persistence (appref-ms):** If configured for offline availability, an application reference file (`.appref-ms` shortcut) is dropped in the user's Start Menu (e.g., `%APPDATA%\Microsoft\Windows\Start Menu\Programs\`).
5.  **Malicious Update Delivery:** The threat actor pushes a malicious update to the ClickOnce deployment server associated with the installed application.
6.  **Execution (Update Mechanism):** When the user next launches the application via the `.appref-ms` shortcut, the built-in ClickOnce update mechanism fetches and executes the malicious update without further user prompting or authorization.
7.  **Impact:** The attacker achieves remote access, facilitates lateral movement, exfiltrates sensitive data, or deploys additional malware.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common protection mechanisms, such as mailbox filtering systems, due to the less scrutinized nature of `.application` files compared to `.exe` files. This technique significantly lowers the barrier to entry for attackers, as no elevated privileges are required for deployment, making standard user accounts vulnerable. Successful exploitation results in stealthy execution within legitimate Microsoft processes, enabling persistent remote access, updating of malware, lateral movement within the network, and potential data exfiltration or further system compromise.

## Recommendation

*   Enable verbose process creation logging for `dfsvc.exe` and `rundll32.exe` to allow detection of suspicious child processes or command-line arguments using the Sigma rules provided.
*   Deploy the "Detect Suspicious ClickOnce Deployment Service Child Processes" Sigma rule to identify unusual executions originating from `dfsvc.exe`.
*   Deploy the "Detect ClickOnce Application Reference File Creation" Sigma rule to monitor for the creation of `.appref-ms` files, especially in unexpected directories or by non-standard processes.
*   Implement strong application control policies to restrict the execution of unsigned or untrusted ClickOnce applications and `.application` files.
*   Educate users on the risks associated with clicking on untrusted links or opening `.application` files from unknown sources, emphasizing that these can install software without typical installation prompts.
