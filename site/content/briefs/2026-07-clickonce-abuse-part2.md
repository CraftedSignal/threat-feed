---
title: Threat Actors Abusing Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are exploiting Microsoft's ClickOnce technology to gain initial access, execute malware, and establish persistence by leveraging its user-friendly deployment, bypassing traditional security controls, operating with low privileges, and utilizing legitimate Windows processes for defense evasion.
date: "2026-07-07T07:42:56Z"
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
  - windows
  - endpoint
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
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: to deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
---

Threat actors are actively abusing Microsoft's ClickOnce technology as a potent attack vector, facilitating initial access, malware execution, and persistent presence on targeted systems. This strategy is highlighted in a recent CrowdStrike report from June 2026, which details how adversaries leverage the inherent design of ClickOnce applications. The user-friendly deployment process, requiring minimal user interaction, allows malicious `.application` files to bypass common security mechanisms like email filters and `.exe` scrutiny. A key advantage for attackers is the ability to deploy ClickOnce apps without requiring elevated administrative privileges, significantly lowering the barrier to entry for attacks on standard user accounts. Furthermore, the malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, aiding in defense evasion. Adversaries can also utilize ClickOnce's built-in update mechanism to push malicious code to already installed applications, achieving reliable persistence and remote access.

## Attack Chain

1.  **Initial Access**: Threat actors convince a user, often through phishing or social engineering, to click a link or button that initiates the download and execution of a malicious `.application` file.
2.  **Execution (ClickOnce Deployment)**: The `.application` file triggers the ClickOnce deployment process, which installs the malicious application with minimal user interaction, often without typical security prompts.
3.  **Defense Evasion/Execution**: The malicious payload embedded within the ClickOnce application executes within legitimate Microsoft Windows processes such as `rundll32.exe` or `dfsvc.exe`, blending with normal system activity.
4.  **Persistence (Shortcut Creation)**: If the ClickOnce application is configured for offline availability, an `.appref-ms` shortcut file for the application is dropped into the user's Start Menu directory (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
5.  **Persistence (Malicious Update)**: The attacker, controlling the ClickOnce deployment server, pushes an update that transforms the initially benign or seemingly harmless application into a malicious one.
6.  **Re-Execution and Persistence**: When the user next launches the application via the `.appref-ms` shortcut, the malicious update is fetched and executed without further user authorization, maintaining attacker presence.
7.  **Persistence (Automated Execution)**: Alternatively, attackers can achieve automated persistence by placing the `.appref-ms` file in the Startup folder or creating a scheduled task to regularly execute the shortcut.
8.  **Impact**: The attacker establishes long-term remote access, enabling further malicious activities such as data exfiltration, lateral movement, or deployment of additional malware.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass traditional security controls that scrutinize `.exe` files, leading to successful initial access and persistence. Since ClickOnce applications do not require elevated privileges for installation, virtually any user account can be targeted, expanding the attack surface within organizations. The execution of malicious payloads within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`) increases stealth and complicates detection. This method provides attackers with sustained remote access and the ability to update their malicious tools covertly, posing a significant risk for data exfiltration, further compromise of systems, and the deployment of advanced malware.

## Recommendation

*   Enable comprehensive `process_creation` logging (e.g., via Sysmon) to monitor for unusual child processes spawned by `rundll32.exe` or `dfsvc.exe`, particularly when their parent process is a web browser or untrusted application.
*   Implement `file_event` logging to detect the creation of `.appref-ms` files in common user directories like `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\`, especially if they originate from untrusted sources.
*   Configure `registry_set` logging to alert on modifications to `Run` keys or new `Scheduled Tasks` that involve `.appref-ms` files, indicating potential persistence attempts.
*   Deploy endpoint detection and response (EDR) solutions capable of analyzing ClickOnce application behavior, focusing on processes initiating from `.application` or `.appref-ms` files.
