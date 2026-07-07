---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are abusing Microsoft's ClickOnce technology to deliver malware, achieve execution, and maintain persistence by leveraging the user-friendly deployment process, requiring minimal user interaction (e.g., clicking a webpage button or .application file), to bypass security defenses that might scrutinize traditional executables, while exploiting ClickOnce's built-in update mechanism to maintain remote access and update malware, and achieving persistence by placing .appref-ms files in locations like the Startup folder or creating scheduled tasks, ensuring malware executes under legitimate Microsoft processes like rundll32.exe and dfsvc.exe.
date: "2026-07-07T08:39:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - persistence
  - defense-evasion
  - windows
  - supply-chain
vendors:
  - Microsoft
products:
  - ClickOnce technology
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
    evidence: ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder [...] they can ensure persist
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
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: All they have to do is push a malicious update into the deployment server, and the next time the user opens the .appref-ms file of the app, the malicious payload will be downloaded and run without the user realizing the application has changed.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect .appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of .appref-ms files in a user's Startup folder, which threat actors use to achieve persistence with ClickOnce applications.
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
  - title: Detect Scheduled Task Creation for ClickOnce Persistence
    description: Detects the creation of scheduled tasks that explicitly reference an .appref-ms file, a known technique for ClickOnce persistence by threat actors.
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

CrowdStrike has identified new and sophisticated abuses of Microsoft's ClickOnce technology by threat actors, building on previous research detailed in Part 1 of their series, with this follow-up published on June 18, 2026. Adversaries are weaponizing ClickOnce due to its user-friendly deployment, which bypasses traditional security scrutiny often applied to `.exe` files, and its ability to install applications without elevated privileges. The malicious activity involves convincing users to click on web links or `.application` files, leading to the deployment of malware via legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`. Furthermore, attackers leverage ClickOnce's built-in update mechanism to maintain remote access and dynamically update their payloads, changing command and control (C2) infrastructure or enabling lateral movement. Persistence is achieved by strategically placing `.appref-ms` files in auto-start locations such as the Windows Startup folder or creating scheduled tasks to re-launch the malicious application, effectively allowing adversaries to "stay forever." This abuse poses a significant risk as it exploits trust in a legitimate Windows feature, often flying under the radar of conventional security tools and user awareness.

## Attack Chain

1.  **Initial Access / Delivery**: The threat actor crafts a malicious web page or email containing a link that, when clicked, initiates the download and deployment of a ClickOnce `.application` file.
2.  **User Execution**: The target user is socially engineered to click the malicious link or directly open a deceptive `.application` file, triggering the ClickOnce installation process.
3.  **Initial Malware Execution**: The ClickOnce application is deployed and executes its initial payload, often leveraging legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe` to launch the malicious code, increasing stealth.
4.  **Persistence - Startup Folder**: The malicious ClickOnce application drops an `.appref-ms` shortcut file into the user's Windows Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`), ensuring re-execution upon system logon.
5.  **Persistence - Scheduled Task**: Alternatively or additionally, the attacker creates a scheduled task that automatically opens the `.appref-ms` file at regular intervals or under specific conditions to maintain execution.
6.  **Command and Control / Update Mechanism**: When the ClickOnce application is launched (either manually by the user or via persistence mechanisms), its `.appref-ms` file triggers an update check with an attacker-controlled deployment server.
7.  **Payload Update and Re-execution**: The attacker pushes a malicious update through the ClickOnce deployment server; the client downloads and executes the updated malicious payload without further user prompting.
8.  **Impact**: The updated malware establishes persistent remote access, facilitates lateral movement within the network, or performs other malicious actions such as data exfiltration or deploying ransomware.

## Impact

The abuse of ClickOnce technology allows threat actors to establish robust and stealthy footholds within victim environments, often bypassing traditional security controls and user scrutiny. If successful, this can lead to sustained remote access, enabling attackers to exfiltrate sensitive data, deploy further malware (including ransomware), and move laterally across the network with minimal detection. The ability to update malware via the legitimate ClickOnce update mechanism ensures resilience against defensive measures and facilitates adaptive attack campaigns. The inherent trust in Microsoft-signed processes like `rundll32.exe` and `dfsvc.exe` during execution further compounds detection challenges, making it difficult for defenders to distinguish malicious activity from benign system operations. While no specific victim counts or sectors are detailed, the broad applicability of ClickOnce suggests potential targeting across various industries.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related persistence.
*   Configure endpoint detection and response (EDR) solutions to monitor `file_event` logs for the creation of `.appref-ms` files in critical directories, particularly the user's Startup folder as described in `Detect .appref-ms Persistence via Startup Folder`.
*   Enable `process_creation` logging for `schtasks.exe` and monitor for command lines that include `.appref-ms` files, as highlighted in `Detect Scheduled Task Creation for ClickOnce Persistence`.
*   Educate users on the risks associated with ClickOnce installations from untrusted sources, emphasizing caution when prompted to install software outside of official application stores or approved channels.
*   Monitor network connections made by `rundll32.exe` and `dfsvc.exe` for suspicious outbound traffic to unusual or known malicious IP addresses and domains.
