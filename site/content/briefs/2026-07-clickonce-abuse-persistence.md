---
title: Threat Actors Abuse ClickOnce Technology for Initial Access and Persistence
slug: 2026-07-clickonce-abuse-persistence
description: Threat actors are leveraging Microsoft's ClickOnce application deployment technology to achieve initial access, bypass traditional security controls, and establish persistence on target systems by convincing users to execute malicious `.application` files which then deploy malware via legitimate processes and can be updated by attackers.
date: "2026-07-07T11:55:48Z"
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
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
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
    evidence: By placing a .appref-ms file in the Startup folder... they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce .appref-ms file within a user's Startup folder, indicating potential persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are increasingly exploiting Microsoft's ClickOnce technology, as highlighted by CrowdStrike, to facilitate initial compromise and maintain long-term access within victim environments. This abuse, documented in June 2026, capitalizes on ClickOnce's user-friendly deployment model, allowing malware to be executed with minimal user interaction by simply clicking a misleading button or `.application` file. Attackers benefit from the technology's ability to operate without elevated privileges and to execute malicious payloads within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), thus bypassing common defenses and flying under the radar of traditional security tools. Furthermore, ClickOnce's built-in update mechanism allows attackers who control the deployment server to remotely update their malware, ensuring persistent access and enabling dynamic command and control. This represents a significant vector for delivering and maintaining sophisticated threats.

## Attack Chain

1.  **Initial Access / Delivery:** Threat actor crafts a social engineering lure (e.g., phishing email, malicious link on a website) prompting the user to interact with a seemingly legitimate ClickOnce application.
2.  **User Execution:** The user clicks a misleading button or opens a malicious `.application` file, initiating the ClickOnce deployment process.
3.  **Payload Execution (Legitimate Processes):** The malicious application's payload is executed by legitimate Microsoft processes such as `dfsvc.exe` and `rundll32.exe`, making it appear as benign system activity.
4.  **Defense Evasion:** Execution within legitimate process trees and the perceived legitimacy of the ClickOnce UI allow the malicious payload to bypass traditional endpoint security controls and user scrutiny.
5.  **Persistence Establishment (Startup Folder):** The attacker configures the deployed ClickOnce application for persistence by placing an `.appref-ms` file in the user's Startup folder (e.g., `%AppData%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).
6.  **Persistence Establishment (Scheduled Task):** Alternatively, the attacker creates a scheduled task to regularly process the `.appref-ms` file, ensuring repeated execution of the malicious application.
7.  **Command and Control / Update:** Utilizing ClickOnce's built-in updating mechanism, the attacker, by controlling the deployment server, pushes updates to the malicious application, changing C2 addresses, moving laterally, or performing other post-exploitation actions.
8.  **Impact:** The attacker gains sustained remote access, enabling further compromise such as data exfiltration, lateral movement, or deployment of additional malware (e.g., ransomware).

## Impact

The abuse of ClickOnce technology allows threat actors to compromise standard user accounts, which constitute the majority of enterprise endpoints, without requiring administrative privileges. Successful exploitation results in the deployment of persistent malware that can evade traditional security defenses due to its execution within legitimate Microsoft processes. This grants attackers continuous remote access, enabling them to update their malicious tools, move laterally within the network, steal sensitive data, or deploy destructive payloads such as ransomware. Organizations face significant risks of data breaches, operational disruption, and financial losses if these attacks are not detected and mitigated early.

## Recommendation

*   Deploy the Sigma rule "Detect ClickOnce .appref-ms Persistence via Startup Folder" to your SIEM and tune it for your environment.
*   Implement application control policies to restrict the execution of unsigned ClickOnce `.application` files or those from untrusted sources.
*   Enhance email and web gateway protections to block `.application` file types at the perimeter and filter suspicious URLs that could host malicious ClickOnce deployments.
*   Enable comprehensive logging for file creation and modification events, particularly within user profile directories like `%AppData%`, to activate the rule above and identify unusual persistence mechanisms.
*   Educate users about the dangers of unsolicited software installations, including those initiated by clicking web links or attachments, even if they appear to originate from legitimate platforms.
