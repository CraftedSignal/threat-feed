---
title: New Abuse of ClickOnce Technology for Initial Access, Execution, and Persistence
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are weaponizing Microsoft's ClickOnce technology to achieve initial access, execution, and persistence by leveraging its user-friendly deployment, lack of user scrutiny, and built-in update mechanism, enabling stealthy malware delivery and continued remote access within legitimate Microsoft process trees.
date: "2026-07-07T07:11:46Z"
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
  - malware
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: users rarely realize that clicking a webpage button can trigger software installation... allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... For instance, by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference file (.appref-ms) within a user's Startup folder, indicating potential persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task
    description: Detects the creation of a scheduled task that executes a ClickOnce application reference file (.appref-ms), indicating potential persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce technology to establish initial access, execute malicious payloads, and maintain persistence on target systems. This new abuse, highlighted in a CrowdStrike report published on June 18, 2026, exploits several features of ClickOnce. Attackers benefit from the technology's minimal user interaction requirement for deployment, allowing them to bypass traditional security controls like mailbox filters. The general lack of awareness among users and security tools regarding `.application` files, compared to `.exe` files, enables payloads to "fly under the radar." Furthermore, ClickOnce applications do not require elevated privileges for installation, broadening the attack surface to standard user accounts. The built-in update mechanism, alongside the execution of malicious payloads within legitimate Microsoft process trees (like `rundll32.exe` and `dfsvc.exe`), makes this a stealthy and effective attack vector for maintaining remote access and updating malware.

## Attack Chain

1.  **Initial Access / User Execution:** Threat actors convince targets to click a malicious link or button, often disguised on a webpage, which initiates the ClickOnce application deployment.
2.  **Execution (Application Deployment):** Upon clicking, a `.application` file is downloaded and executed, triggering the installation of the ClickOnce application with minimal user prompts.
3.  **Malicious Payload Delivery:** The ClickOnce application, containing the adversary's malware, is downloaded and installed onto the user's system without requiring administrator privileges.
4.  **Defense Evasion (Legitimate Process Execution):** The malicious payload executes within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, masking its activity and increasing stealth.
5.  **Persistence (Shortcut Placement):** To maintain persistence, the attacker ensures that an application reference file (`.appref-ms`) for the malicious ClickOnce app is placed in the user's Startup folder.
6.  **Persistence (Scheduled Task Creation):** Alternatively, adversaries may create a scheduled task to regularly process the `.appref-ms` file, ensuring repeated execution of the malicious application.
7.  **Command and Control / Updates:** Leveraging the ClickOnce application's built-in update mechanism, the threat actor can remotely push updates to the deployed application, allowing for changes to C2 addresses, lateral movement capabilities, or new malware components.
8.  **Impact:** The attacker gains continuous remote access to the compromised system, can perform lateral movement, and update their tools or payloads at will.

## Impact

The observed abuse of ClickOnce technology allows threat actors to gain and maintain persistent remote access to victim systems without requiring elevated privileges. This significantly lowers the barrier to entry for attacks, as standard user accounts can be compromised, which constitute the majority of enterprise endpoints. Successful exploitation leads to stealthy execution of malicious payloads within legitimate Microsoft processes, making detection difficult. The built-in update mechanism ensures attackers can modify their malware, change command and control infrastructure, and facilitate lateral movement, leading to comprehensive compromise and potential data exfiltration or further system infection.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence.
*   Monitor for the creation of `.appref-ms` files in user Startup folders, specifically focusing on `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`.
*   Monitor for scheduled tasks that execute `.appref-ms` files, looking for suspicious task names or arguments.
*   Implement application whitelisting to restrict the execution of unsigned or untrusted ClickOnce applications.
*   Enhance user awareness training about the risks associated with clicking on unfamiliar links or buttons that trigger software installations, especially for applications deployed via web browsers.
