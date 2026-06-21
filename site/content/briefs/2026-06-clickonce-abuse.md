---
title: New Abuse of ClickOnce Technology for Initial Access and Persistence
slug: 2026-06-clickonce-abuse
description: Threat actors are weaponizing Microsoft's ClickOnce technology to achieve initial access, execution, and persistence on target systems, leveraging its user-friendly deployment and update mechanisms to bypass traditional security defenses and maintain remote access without requiring administrative privileges, executing payloads within legitimate Microsoft process trees.
date: "2026-06-21T05:32:16Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - clickonce
  - windows
  - initial-access
  - persistence
  - defense-evasion
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
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect dfsvc.exe Spawning Suspicious Child Processes
    description: Detects instances where the legitimate Windows ClickOnce Deployment Services (dfsvc.exe) spawns known suspicious processes (e.g., scripting interpreters, downloaders), which could indicate the execution of a malicious ClickOnce application payload.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious .appref-ms File Creation Outside Start Menu
    description: Detects the creation of ClickOnce shortcut files (.appref-ms) in directories other than the standard Windows Start Menu paths, indicating potential persistence from a non-standard or malicious ClickOnce application deployment.
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
  - title: Detect Execution of .application File by Script Interpreters
    description: Detects attempts to directly execute ClickOnce `.application` deployment files via command-line interpreters or scripting hosts, which deviates from typical ClickOnce initiation and may indicate an attacker attempting to force deployment or execute a malicious manifest.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Recent observations highlight a novel abuse of Microsoft's ClickOnce technology by threat actors, focusing on its features for initial access, execution, and persistence. This technique, reported by CrowdStrike in June 2026, exploits the inherent trust and minimal user interaction required for ClickOnce application deployment. Attackers leverage this to distribute malicious payloads, bypassing common security mechanisms like email filters that scrutinize `.exe` files but may overlook `.application` files. The method allows for the deployment of malware without requiring administrative privileges, broadening the scope of potential victims to standard user accounts. Furthermore, ClickOnce's built-in update mechanism is co-opted to maintain remote access, update C2 infrastructure, or facilitate lateral movement, all while masquerading within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`, significantly enhancing stealth and defense evasion capabilities.

## Attack Chain

1.  **Initial Access via User Interaction**: Threat actors convince targets to click on a malicious link or open an `.application` file, often via misleading buttons or phishing campaigns, initiating a ClickOnce application deployment.
2.  **Deployment of Malicious ClickOnce Application**: The user interaction triggers the download and execution of a weaponized ClickOnce application, which contains or ultimately delivers the malicious payload.
3.  **Execution within Legitimate Processes**: The malicious payload is executed within the context of legitimate Microsoft processes, primarily `dfsvc.exe` (Deployment Services Client) or `rundll32.exe`, to evade detection.
4.  **Persistence via `.appref-ms` file**: A shortcut file with the `.appref-ms` extension is dropped in the user's Start Menu directory (`%Users%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`) by the ClickOnce framework, ensuring the malicious application can be re-launched.
5.  **Utilizing Built-in Update Mechanism**: Once persisted, the attacker can push malicious updates to the application's deployment server. When the user next launches the application via the `.appref-ms` shortcut, the update mechanism fetches and executes the updated malicious payload without further user prompting.
6.  **Remote Access and C2 Maintenance**: The updated malicious application can establish persistent remote access, update its command and control (C2) infrastructure, or perform other post-exploitation activities like data exfiltration.
7.  **Lateral Movement (Potential)**: Through the maintained remote access and updated C2, attackers can initiate lateral movement within the compromised network.

## Impact

Successful exploitation of ClickOnce technology allows attackers to gain persistent access to targeted systems, bypassing traditional security controls and executing payloads under the guise of legitimate Microsoft processes. This enables capabilities such as remote code execution, data exfiltration, and the establishment of long-term command and control. The lack of administrative privilege requirements means a wider range of user accounts are vulnerable. The ease of payload delivery, coupled with the ability to silently update malware, poses a significant risk for continued compromise and facilitates further malicious activities including ransomware deployment or corporate espionage across targeted organizations in various sectors.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Enable Sysmon process-creation and file-event logging to activate the rules above.
*   Monitor for process creations where `dfsvc.exe` is the parent and the child process is not a known, legitimate application.
*   Educate users on the risks associated with clicking on links or opening `.application` files from untrusted sources, even if they appear to initiate a software installation.
*   Implement application whitelisting solutions to prevent the execution of unauthorized ClickOnce applications or executables launched by them.
