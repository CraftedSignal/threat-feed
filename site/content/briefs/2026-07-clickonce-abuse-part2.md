---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology for initial access, execution, persistence, and defense evasion by deploying malicious `.application` files or leveraging built-in update mechanisms via `.appref-ms` files to maintain remote access and execute malware within legitimate Microsoft processes without requiring elevated privileges.
date: "2026-07-07T15:29:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - initial-access
  - persistence
  - defense-evasion
  - command-and-control
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed... Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
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
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses... All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
iocs:
  - type: file
    value: .application files
  - type: file
    value: .appref-ms
ioc_counts:
  file: 2
rules:
  - title: Detect ClickOnce .appref-ms File Creation in Startup Folder
    description: Detects the creation or modification of ClickOnce application reference files (.appref-ms) in a user's Startup folder, which is a known persistence mechanism for attackers.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Execution of ClickOnce .appref-ms from Persistence Paths
    description: Detects `dfsvc.exe` or `rundll32.exe` being invoked with command-line arguments pointing to a ClickOnce application reference file (.appref-ms) located in a known persistence path (e.g., Startup folder), indicating potential malicious execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1218.011
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has observed threat actors actively weaponizing Microsoft's ClickOnce technology, primarily for initial access, persistence, defense evasion, and establishing command and control. This abuse, detailed in a recent report, highlights how attackers bypass traditional security controls by leveraging the user-friendly nature of ClickOnce deployments. By convincing targets to click a malicious link or open a seemingly benign `.application` file, adversaries can install malware without requiring administrative privileges, often flying under the radar of security tools that scrutinize `.exe` files more heavily. Once deployed, the built-in update mechanism of ClickOnce applications, especially those configured for offline availability, allows attackers to maintain remote access and update their malware by pushing malicious components from their controlled servers. This technique, coupled with the execution of payloads within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, significantly increases the stealth and effectiveness of these attacks, posing a critical threat to enterprise endpoints.

## Attack Chain

1.  **Initial Access (Malicious Link/File)**: Threat actors deliver malicious ClickOnce applications by convincing users to click a deceptive link on a webpage or in a phishing email, or by directly opening a malicious `.application` file.
2.  **Execution (ClickOnce Deployment)**: Upon user interaction, the ClickOnce application deployment process initiates, downloading and installing initial components from an attacker-controlled server.
3.  **Defense Evasion (Legitimate Processes)**: The malicious payload executes within legitimate Microsoft process trees, specifically `rundll32.exe` and `dfsvc.exe`, to evade detection and appear as benign system activity.
4.  **Persistence (Shortcut/Scheduled Task)**: For applications configured for offline availability, an `.appref-ms` shortcut file is dropped into the Windows Start Menu. Attackers can then leverage this for persistence by placing the `.appref-ms` file in the Startup folder (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) or by creating a scheduled task to regularly execute the `.appref-ms` file.
5.  **Command and Control (Update Mechanism)**: When the persisted `.appref-ms` file is opened (e.g., on system startup or by scheduled task), it triggers the ClickOnce update mechanism, fetching new or updated malicious components from the attacker's deployment server.
6.  **Further Execution (Malware Delivery)**: The updated components, now malicious, are downloaded and executed without further user prompts, enabling the attacker to maintain remote access, change C2 addresses, move laterally, and deploy additional malware.
7.  **Impact**: The final objective typically involves data exfiltration, deployment of ransomware, or other forms of system compromise leveraging the established persistent access.

## Impact

This abuse of ClickOnce technology can lead to significant organizational damage, as it facilitates stealthy initial access and persistent control over compromised systems. Organizations are at risk of widespread malware infections, including ransomware and infostealers, due to the ease with which attackers can bypass traditional security defenses and maintain remote access. The lack of awareness around ClickOnce applications means users often unwittingly trigger software installations, expanding the attack surface. While specific victim counts are not provided in the source, the technique's effectiveness against standard user accounts and its ability to bypass email filtering systems suggest a broad impact across various enterprise sectors where Windows endpoints are prevalent.

## Recommendation

*   Deploy the Sigma rule "Detect ClickOnce .appref-ms File Creation in Startup Folder" to your SIEM to alert on `.appref-ms` files being placed in user Startup folders.
*   Deploy the Sigma rule "Detect Execution of ClickOnce .appref-ms from Persistence Paths" to monitor for `dfsvc.exe` or `rundll32.exe` being invoked with `.appref-ms` from suspicious or persistence locations.
*   Educate users on the risks associated with clicking links from untrusted sources and opening `.application` files.
*   Enhance endpoint detection and response (EDR) visibility to include `dfsvc.exe` and `rundll32.exe` process activity, especially child process creation or network connections to untrusted domains.
