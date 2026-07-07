---
title: New Abuse of ClickOnce Technology for Persistence and C2
slug: 2026-07-clickonce-abuse-part-2
description: Threat actors are abusing Microsoft's ClickOnce technology for initial access, execution, and persistence on target systems by leveraging its user-friendly deployment, lack of user awareness regarding '.application' files, and ability to install without elevated privileges, allowing them to bypass traditional defenses and push malicious updates for remote access and C2.
date: "2026-07-04T01:03:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - microsoft
  - clickonce
  - initial-access
  - persistence
  - defense-evasion
  - execution
  - command-and-control
vendors:
  - Microsoft
products:
  - ClickOnce
  - Microsoft Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: users rarely realize that clicking a webpage button can trigger software installation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe).
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries, rather than directly running malicious payloads. For instance, by placing a .appref-ms file in the Startup folder.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By definition, .appref-ms files trigger the execution of a ClickOnce application upon opening. When placed strategically, adversaries can automate their opening to use them as intermediaries... or creating a scheduled task.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: When opened, the .appref-ms gets the ClickOnce components to fetch available updates from the deployment server, download any potential new components, and run the application. ... All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: ClickOnce .appref-ms File Created in Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference file (.appref-ms) within a Windows Startup folder, indicating a persistence mechanism. This could be used by attackers to launch malicious applications automatically.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Scheduled Task Creation for ClickOnce .appref-ms File
    description: Detects the creation of a scheduled task that executes a ClickOnce application reference file (.appref-ms), indicating a persistence mechanism. Attackers can use this to ensure their malicious ClickOnce application is launched regularly or on system events.
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

Threat actors are actively abusing Microsoft's ClickOnce technology, as detailed by CrowdStrike, to gain initial access, execute payloads, and establish persistence on target systems. This new abuse vector leverages the inherent features of ClickOnce, which facilitate software deployment with minimal user interaction, often bypassing traditional security controls like email filtering. Attackers capitalize on a general lack of awareness surrounding `.application` files and ClickOnce installers, which allows them to trick users into deploying malicious applications without requiring elevated privileges. Once installed, the built-in update mechanism of ClickOnce is exploited to deliver malicious updates, establish command and control (C2), maintain remote access, and facilitate lateral movement. The stealthiness of this method is further enhanced as malicious payloads execute within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. This makes it a potent attack vector that demands immediate attention from security teams.

## Attack Chain

1.  **Initial Access**: Threat actors craft malicious `.application` or web pages designed to trigger a ClickOnce deployment.
2.  **User Execution**: The target user is socially engineered into clicking a link or opening an `.application` file, initiating the ClickOnce installation process.
3.  **Application Deployment**: The ClickOnce deployment service (`dfsvc.exe`) and `rundll32.exe` execute, installing the application and dropping an `.appref-ms` file.
4.  **Persistence (Shortcut)**: A legitimate `.appref-ms` shortcut file is placed in the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) for offline application access.
5.  **Persistence (Strategic Placement)**: Adversaries can strategically place the `.appref-ms` file in the Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`) or create a scheduled task to automatically open the `.appref-ms` file upon system boot or at specific intervals.
6.  **Malicious Update / Command and Control (C2)**: When the user (or automated persistence mechanism) next launches the application via the `.appref-ms` file, the ClickOnce client fetches updates from the attacker-controlled server.
7.  **Payload Delivery & Execution**: The attacker pushes a malicious update, transforming the benign application into malware, which is then downloaded and executed on the victim's machine without further user prompts.
8.  **Impact**: The attacker gains remote access, can change C2 addresses, move laterally within the network, and perform other malicious activities.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and control over compromised systems, often bypassing traditional security mechanisms. The ability to deploy applications without elevated privileges lowers the barrier for attackers, making standard user accounts vulnerable. Once established, adversaries can leverage the built-in update mechanism to push new malicious payloads, facilitating remote access, changing command and control (C2) infrastructure, and enabling lateral movement within the compromised network. While the specific number of victims or targeted sectors are not enumerated, the technique's stealth and efficacy make it a significant threat to any organization utilizing Windows environments, potentially leading to data exfiltration, further compromise, or ransomware deployment.

## Recommendation

*   **Deploy the Sigma rules** provided in this brief to your SIEM and tune them for your environment to detect suspicious ClickOnce persistence mechanisms.
*   **Enable Sysmon file event logging** for `TargetFilename` and `TargetDirectory` to activate detection rules for `.appref-ms` files.
*   **Enable Sysmon process creation logging** for `schtasks.exe` and `CommandLine` to detect suspicious scheduled task creations related to `.appref-ms` files.
*   **Educate users** on the risks associated with `.application` files and unexpected software installation prompts, even if they appear legitimate.
