---
title: New Abuse of ClickOnce Technology for Persistence and Evasion
slug: 2026-07-clickonce-abuse
description: Threat actors are weaponizing Microsoft's ClickOnce application deployment technology, specifically its built-in update mechanism and `.appref-ms` files, to achieve stealthy execution and persistence without requiring elevated privileges, thereby bypassing traditional security controls and user scrutiny.
date: "2026-07-07T14:51:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - initial-access
  - evasion
  - clickonce
  - windows
  - supply-chain
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Another advantage of ClickOnce applications for adversaries lies in the fact that they don’t require elevated privileges to be deployed. While installing a .msi package requires administrator rights, any user can install a ClickOnce app.
    confidence_band: med
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
  - title: Detect ClickOnce Appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application shortcut (.appref-ms) within a user's Startup folder, indicating potential persistence.
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
  - title: Detect Suspicious ClickOnce Application Launch by Dfsvc.exe
    description: Detects dfsvc.exe (Deployment Services Client) launching an application with command-line arguments that deviate from standard ClickOnce deployment, indicating potential malicious update or execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has identified a new method by which threat actors are abusing Microsoft's ClickOnce technology to simplify malware delivery, achieve persistence, and evade detection. This abuse leverages the user-friendly deployment process, which requires minimal interaction, and the general lack of awareness surrounding ClickOnce applications. By convincing users to click a link or button that initiates a ClickOnce application installation, attackers can deploy seemingly benign applications. The core of this new abuse lies in exploiting the `.appref-ms` shortcut files and the legitimate update mechanism of ClickOnce. This allows threat actors to transform a previously installed, harmless application into a malicious one by pushing updates to a controlled deployment server, and subsequently maintaining remote access and updating malware. The technique benefits from executing within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, further increasing stealth.

## Attack Chain

1.  **Initial Access**: Threat actors convince a user to click a malicious link or button, often via phishing, leading to the download and execution of a `.application` file.
2.  **Initial Application Deployment**: The user is prompted to install a seemingly benign ClickOnce application, requiring minimal clicks, without needing administrator privileges.
3.  **Shortcut File Creation**: Upon installation, a shortcut file with the `.appref-ms` extension is dropped in the user's Start Menu (e.g., `%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
4.  **Malicious Update Staging**: The threat actor, controlling the deployment server, pushes a malicious update for the installed ClickOnce application.
5.  **Persistence Establishment**: The threat actor places the `.appref-ms` file into the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`) or configures a scheduled task to regularly execute the `.appref-ms` file.
6.  **Malicious Payload Delivery via Update**: When the user logs in or the scheduled task runs, the `.appref-ms` file triggers the ClickOnce components to check for updates from the attacker's server, downloading and running the malicious payload.
7.  **Stealthy Execution**: The malicious payload executes within legitimate Microsoft processes (`rundll32.exe`, `dfsvc.exe`), making it difficult to distinguish from benign system activity.
8.  **Impact**: The attacker maintains persistent access to the system, enabling further actions like command and control, data exfiltration, or lateral movement.

## Impact

The abuse of ClickOnce technology allows threat actors to gain persistent access to targeted systems with minimal user interaction and without requiring administrative privileges, affecting any standard user account. This technique significantly simplifies the delivery and persistence phases of attacks, enabling adversaries to bypass common protection mechanisms like email filtering for executables. The execution within legitimate Microsoft processes grants high stealth, making it challenging for security tools and users to identify malicious activity. If successful, this can lead to long-term compromise, data exfiltration, deployment of additional malware, or serve as a beachhead for lateral movement within an organization's network.

## Recommendation

*   Enable Sysmon `FileCreation` and `ProcessCreate` event logging to activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Educate users on the risks associated with installing applications from untrusted sources, even if they appear to be legitimate pop-ups or simplified installers.
*   Implement application control policies to restrict the execution of `.application` and `.appref-ms` files, especially when not signed by trusted publishers or originating from unapproved locations.
