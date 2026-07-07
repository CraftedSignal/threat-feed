---
title: 'New Abuse of ClickOnce Technology: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are exploiting Microsoft's ClickOnce technology to achieve initial access, execute malicious payloads, and maintain persistence. This abuse leverages ClickOnce's user-friendly deployment, minimal privilege requirements, and built-in update mechanism to bypass traditional security defenses and execute malware stealthily within legitimate Microsoft processes like rundll32.exe. Adversaries achieve persistence by pushing malicious updates, or by placing ClickOnce shortcut files (.appref-ms) in the Windows Startup folder or configuring them as scheduled tasks.
date: "2026-07-07T15:05:24Z"
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
  - remote-access
  - microsoft
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
  - .application files
  - .appref-ms files
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
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
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce Deployment Service (dfsvc.exe) Spawning Scripting/Shell Processes
    description: Detects suspicious child process creation by dfsvc.exe (ClickOnce Deployment Services), indicating potential execution of malicious payloads via ClickOnce applications. Legitimate ClickOnce apps rarely spawn scripting engines directly from dfsvc.exe.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Persistence via Startup Folder
    description: Detects the creation or modification of .appref-ms files in a user's Startup folder. This is a common persistence mechanism employed by threat actors using malicious ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike has observed a new abuse of Microsoft's ClickOnce technology by threat actors to facilitate initial access, execute malicious payloads, and establish persistence on target systems. Beginning as early as June 2026, this technique exploits the inherent user-friendliness and low-privilege requirements of ClickOnce application deployment, often bypassing traditional security controls like email filtering. Threat actors deliver malicious `.application` files, leveraging user unfamiliarity with ClickOnce installations to trick victims into executing malware. Once deployed, these applications run within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, enhancing stealth. Persistence is achieved by placing `.appref-ms` files in the Windows Startup folder or registering them as scheduled tasks, ensuring malware re-execution. The built-in update mechanism of ClickOnce further allows attackers to update their malware, change command and control (C2) infrastructure, or facilitate lateral movement, creating a highly potent and stealthy attack vector for remote access and data exfiltration.

## Attack Chain

1.  **Initial Access**: Threat actors send phishing emails containing links or direct users to malicious websites that prompt them to "click a button" for a supposed application or document.
2.  **Delivery**: The user clicks the link, triggering the download and execution of a malicious `.application` file (a ClickOnce deployment manifest).
3.  **Execution**: The ClickOnce runtime components, specifically `dfsvc.exe` (Deployment Services) and `rundll32.exe`, legitimately process the `.application` file and execute the embedded malicious payload without requiring administrator privileges.
4.  **Payload Deployment**: The malicious ClickOnce application installs its payload (e.g., a backdoor, infostealer, or remote access tool) onto the system, often in user-writable ClickOnce application cache directories like `%LOCALAPPDATA%\Apps\2.0\`.
5.  **Persistence via Startup Folder**: To maintain access, the attacker places the malicious application's `.appref-ms` shortcut file directly into the user's Windows Startup folder (`%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).
6.  **Persistence via Scheduled Task**: Alternatively, the attacker creates a Scheduled Task to regularly execute the malicious ClickOnce application by referencing its `.appref-ms` file, ensuring repeated execution upon system events or specific intervals.
7.  **Command and Control / Updates**: The malicious ClickOnce application uses its built-in update mechanism to communicate with a threat actor-controlled server, fetching new components, receiving updated instructions, or changing C2 infrastructure for continued remote access.
8.  **Impact**: The attacker achieves persistent remote access, enabling further actions such as data exfiltration, lateral movement, or the deployment of additional malware like ransomware.

## Impact

This ClickOnce abuse creates a significant impact by bypassing common enterprise security mechanisms due to its reliance on legitimate Microsoft technology and minimal user interaction. Organizations targeted may experience unauthorized access, data exfiltration, and persistent footholds for threat actors without requiring elevated privileges. The stealthy execution within trusted Microsoft processes makes detection challenging, leading to prolonged compromise and potentially significant financial and reputational damage. The lack of user awareness regarding ClickOnce installations also makes users highly susceptible to social engineering, contributing to a high success rate for initial access.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Configure endpoint detection and response (EDR) solutions to monitor `dfsvc.exe` for unusual child process creation, especially scripting engines, as covered by "Detect ClickOnce Deployment Service (dfsvc.exe) Spawning Scripting/Shell Processes".
*   Enhance file integrity monitoring and process creation logging to detect the creation of `.appref-ms` files in user Startup folders, specifically addressing the behavior described in "Detect ClickOnce Persistence via Startup Folder".
*   Educate users about the risks associated with installing software from untrusted sources, even if it appears to be a "one-click" installation, emphasizing the dangers of `.application` files.
*   Implement application whitelisting or strict software restriction policies to prevent the execution of applications from user-writable directories like `AppData` where ClickOnce applications are commonly installed.
