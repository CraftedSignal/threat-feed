---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology by distributing malicious applications that exploit its built-in update mechanism and persistence features to achieve stealthy code execution and long-term access with minimal user interaction and no elevated privileges.
date: "2026-07-04T10:59:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - execution
  - windows
  - social-engineering
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: creating a scheduled task
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
    description: Detects the creation of .appref-ms files in the Windows Startup folder, a known technique for ClickOnce persistence described by threat actors.
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
    description: Detects the creation of scheduled tasks that explicitly execute a ClickOnce .appref-ms file, a technique used by threat actors for persistence.
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

CrowdStrike warns of a new and evolving abuse of Microsoft's ClickOnce technology by threat actors, building on previous research from 2019. This technique leverages ClickOnce's user-friendly deployment and built-in updating mechanisms to bypass traditional security controls, enabling stealthy malware execution and persistence. Adversaries can convince targets to install seemingly innocuous ClickOnce applications with minimal interaction and no elevated privileges. Once installed, the `.appref-ms` shortcut provides a robust persistence mechanism, either through placement in startup folders or via scheduled tasks. This allows attackers to push malicious updates from their controlled servers, ensuring the downloaded payload executes discreetly within legitimate Windows process trees (like rundll32.exe and dfsvc.exe). The primary goal is to maintain remote access, change command and control infrastructure, facilitate lateral movement, or exfiltrate data, making it a powerful and difficult-to-detect attack vector.

## Attack Chain

1.  **Initial Access:** Threat actors craft a malicious ClickOnce application, potentially mimicking a legitimate one, and host it on a controlled server.
2.  **User Execution (Lure):** Users are lured, typically via phishing campaigns or social engineering, into clicking a link or opening an `.application` file that initiates the ClickOnce deployment process.
3.  **Application Installation:** The user is prompted to install the ClickOnce application, requiring minimal interaction and no elevated administrative privileges for successful deployment.
4.  **Persistence Establishment:** An `.appref-ms` shortcut file for the application is dropped in the user's Start Menu (e.g., `%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`). The attacker may then place this `.appref-ms` file in the Startup folder or create a scheduled task to automatically launch it.
5.  **Malicious Update Deployment:** The threat actor updates the application components hosted on their deployment server with malicious code.
6.  **Malware Execution (Update):** Upon subsequent execution of the ClickOnce application (either manually by the user via the shortcut or automatically via the persistence mechanism), the malicious update is fetched, downloaded, and executed discreetly within legitimate Windows process trees, often involving `rundll32.exe` and `dfsvc.exe`.
7.  **Command and Control (C2):** The executed malware establishes communication with attacker-controlled C2 infrastructure for further instructions or data exfiltration.
8.  **Impact:** The attacker maintains persistent remote access, enabling further actions like lateral movement, data theft, or deployment of additional payloads (e.g., ransomware).

## Impact

Successful exploitation of this ClickOnce abuse vector leads to unauthorized code execution and persistent access on targeted systems without requiring administrative privileges. Threat actors gain a reliable method for maintaining remote access, updating their malware, and pivoting to other attack objectives like command and control (C2), lateral movement, or data exfiltration. The stealthy nature of execution within legitimate Microsoft processes further complicates detection, allowing attackers to evade security tools and remain undetected for longer periods. While the article does not specify victim counts or particular sectors, the broad applicability of ClickOnce means any organization utilizing Windows endpoints is potentially at risk of compromise, leading to data breaches, ransomware, or intellectual property theft.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Enable comprehensive process creation logging (e.g., Sysmon Event ID 1) and file creation logging (e.g., Sysmon Event ID 11) on all Windows endpoints to capture the activities described in the rules above.
*   Educate users on the risks of unsolicited software installations and the deceptive nature of ClickOnce prompts, which often appear legitimate but can deliver malicious payloads.
*   Implement application whitelisting solutions to prevent the execution of unauthorized ClickOnce applications, especially those originating from untrusted sources.
