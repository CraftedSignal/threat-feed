---
title: 'New Abuse of the ClickOnce Technology: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse
description: Threat actors are actively abusing Microsoft's ClickOnce technology to gain initial access, achieve persistence, and execute malware stealthily, bypassing traditional defenses by leveraging legitimate application deployment mechanisms and user interaction.
date: "2026-07-05T07:06:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - initial-access
  - persistence
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Microsoft Windows (ClickOnce Applications)
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
    technique_id: T1204
    technique_name: User Execution
    evidence: Threat actors only need to convince their target to click once or twice to potentially get their malware executed... This allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
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
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence
    description: Detects the creation of .appref-ms files in the Windows Startup folder, a known persistence mechanism leveraged by threat actors abusing ClickOnce technology.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1204.002
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Threat actors are increasingly weaponizing Microsoft's ClickOnce technology, a legitimate application deployment framework, to deliver malicious payloads, establish persistence, and execute code stealthily. This new abuse, highlighted in June 2026, leverages ClickOnce's user-friendly deployment process, requiring minimal user interaction to install software, often bypassing traditional security measures like mailbox filtering. Attackers benefit from a general lack of awareness around `.application` files and the fact that ClickOnce apps do not require elevated privileges for installation. The malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, enhancing stealth. Furthermore, the built-in update mechanism of ClickOnce applications, specifically through `.appref-ms` files, allows threat actors to remotely update malware and maintain remote access without user re-authorization. This creates a powerful and often overlooked attack vector.

## Attack Chain

1.  **Initial Access (User Interaction)**: Threat actors convince a target user to click a malicious link or button, often embedded in a phishing email or website, which initiates the ClickOnce application deployment.
2.  **Payload Delivery (.application file)**: The user's interaction triggers the download and execution of a malicious ClickOnce `.application` file or directly deploys the application.
3.  **Low-Privilege Installation**: The ClickOnce application installs its components on the system without requiring administrative privileges, allowing attacks on standard user accounts.
4.  **Stealthy Execution**: The initial malicious payload executes within legitimate Microsoft system processes, such as `rundll32.exe` and `dfsvc.exe`, making it difficult for traditional security tools to flag as suspicious.
5.  **Persistence via `.appref-ms` Shortcut**: For applications configured to be available offline, a shortcut file (`.appref-ms`) is placed in the user's Start Menu (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
6.  **Automated Persistence (Startup/Scheduled Task)**: Adversaries further establish persistence by strategically placing the `.appref-ms` file in the Windows Startup folder or by creating a scheduled task to automatically launch the malicious ClickOnce application upon system boot or at specific intervals.
7.  **Update Mechanism Abuse**: When the `.appref-ms` shortcut is launched, the ClickOnce client fetches updates from the deployment server. Threat actors, controlling the server (either compromised or initially malicious), can push malicious updates to transform a benign application into malware without further user prompts.
8.  **Command and Control / Impact**: The updated malicious application gains persistent remote access, enabling further actions such as changing C2 addresses, lateral movement, data exfiltration, or deploying additional malware.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common protection mechanisms like mailbox filtering systems and circumvent traditional security tools that scrutinize executable files more heavily than `.application` files. Successful attacks lead to malware execution, persistent remote access to enterprise endpoints without requiring administrative privileges, and the ability for attackers to update their malware components unnoticed. This significantly increases the risk of data exfiltration, lateral movement within the network, and broader system compromise, impacting the majority of enterprise endpoints which typically run with standard user accounts.

## Recommendation

*   Deploy the Sigma rule "Detect ClickOnce `.appref-ms` Persistence" to your SIEM to identify suspicious `.appref-ms` file creation in known persistence locations.
*   Monitor process creation events for `rundll32.exe` and `dfsvc.exe` that exhibit unusual parent-child relationships or initiate suspicious network connections, as these are legitimate processes abused by ClickOnce malware.
*   Educate users on the risks associated with clicking on links or opening `.application` files from untrusted sources, even if they appear to initiate a legitimate installation process.
