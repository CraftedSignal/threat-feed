---
title: New Abuse of ClickOnce Technology for Malware Delivery and Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively leveraging Microsoft's ClickOnce technology for stealthy malware delivery, persistence, and command and control, exploiting its legitimate features like minimal user interaction, execution within trusted processes, and built-in updating mechanisms to bypass traditional security defenses and maintain remote access.
date: "2026-07-06T04:24:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - malware-delivery
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: On the other hand, users rarely realize that clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first. This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism. When configured to be available offline, an application reference file (.appref-ms) is dropped at the installation of the application in the Start Menu (under %Users \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\). This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Suspicious ClickOnce dfsvc.exe Child Process Creation
    description: Detects suspicious child processes spawned by dfsvc.exe, a legitimate ClickOnce component, which could indicate compromise or malicious activity using ClickOnce as a proxy.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: ClickOnce .appref-ms Persistence in Startup Folder
    description: Detects the creation of .appref-ms shortcut files directly in the Windows Startup folder, a common method for attackers to establish persistence using abused ClickOnce applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Scheduled Task Creation for ClickOnce Persistence
    description: Detects the creation of scheduled tasks that are configured to execute ClickOnce .appref-ms files, indicating a potential persistence mechanism for malicious applications.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

CrowdStrike has identified new abuses of Microsoft's ClickOnce technology, building on previous research, to deliver and persist malware on victim systems. This technique leverages the inherent trust and low friction of ClickOnce deployments, allowing threat actors to execute payloads with minimal user interaction, often by simply convincing targets to click a link. The malicious activity runs within legitimate Microsoft processes like `rundll32.exe` and `dfsvc.exe`, increasing stealth and evading traditional `.exe` focused defenses. Attackers further exploit ClickOnce's built-in update mechanism for persistent remote access and malware updates, and achieve persistence by placing `.appref-ms` shortcut files in the Windows Startup folder or creating scheduled tasks. This method is effective due to a general lack of awareness regarding ClickOnce security implications, enabling attackers to target standard user accounts and bypass typical security controls.

## Attack Chain

1.  Threat actor crafts a malicious ClickOnce application, potentially by modifying a benign application or creating a new one with a malicious payload.
2.  Attacker socially engineers a victim to initiate the deployment of the malicious ClickOnce application, often via a deceptive link or button on a webpage or within an email.
3.  Victim clicks the link, triggering the download and deployment of the `.application` file with minimal security prompts, due to the user-friendly nature of ClickOnce.
4.  The malicious payload executes on the victim's system, often proxied through legitimate Microsoft ClickOnce components such as `rundll32.exe` and `dfsvc.exe`.
5.  The ClickOnce application, configured for offline availability, drops an `.appref-ms` shortcut file into the user's Start Menu (`%Users\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\`).
6.  For persistence, the attacker places the `.appref-ms` file into the Windows Startup folder (`%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`) or creates a scheduled task to launch it automatically.
7.  The attacker utilizes the ClickOnce application's built-in updating mechanism to push further malicious updates to the deployed application, enabling changes to command and control (C2) infrastructure or the delivery of additional malware.
8.  This allows the attacker to maintain remote access, update their tools, exfiltrate data, or perform lateral movement within the compromised environment, without requiring further user interaction.

## Impact

The abuse of ClickOnce technology allows threat actors to establish persistent access and execute arbitrary code on victim systems, often bypassing initial access defenses and remaining undetected due to execution within trusted processes. This leads to potential data exfiltration, further compromise of the network through lateral movement, and the deployment of additional malicious payloads such as ransomware or espionage tools. The ease of deployment and low user awareness mean that a wide range of organizations and standard user accounts are vulnerable. The built-in updating mechanism grants attackers a reliable, low-friction method to continuously adapt their malware, making remediation challenging and enabling long-term compromise without re-engaging the user.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce-related activities.
*   Enable Sysmon process-creation and registry-event logging to activate the rules above, especially for `dfsvc.exe` and `rundll32.exe` child processes, and `.appref-ms` file creations.
*   Implement application whitelisting to prevent unauthorized ClickOnce applications from deploying or executing.
*   Educate users about the risks associated with installing software from unverified sources, even when presented with what appear to be legitimate system prompts.
