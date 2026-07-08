---
title: New Abuse of ClickOnce Technology for Stealthy Persistence
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively abusing Microsoft's ClickOnce technology to achieve initial access, execute malicious payloads, and maintain persistence with stealth by leveraging its legitimate deployment and update mechanisms, bypassing traditional security controls and targeting standard user accounts.
date: "2026-07-08T06:19:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - persistence
  - delivery
  - windows
  - microsoft-technology
  - defense-evasion
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
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: clicking a webpage button can trigger software installation, typically expecting to see an executable installer in their downloads folder first. This lack of knowledge of the ClickOnce technology allows threat actors to use misleading buttons and fool users who don’t realize that clicking on it can trigger an application’s deployment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: by placing a .appref-ms file in the Startup folder
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: or creating a scheduled task to process the file regularly, they can ensure persistence
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: While .exe files are heavily scrutinized and controlled in most environments, .application files can sometimes fly under the radar of security tools, creating an opportunity for threat actors to slip through traditional defenses.
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
    evidence: ClickOnce applications also provide threat actors with a built-in updating mechanism. ... This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce (.appref-ms) Persistence via Startup Folder
    description: Detects the creation of ClickOnce application reference files (.appref-ms) in user Startup folders, a known persistence technique used by threat actors.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce (.appref-ms) Persistence via Scheduled Task Creation
    description: Detects the creation of scheduled tasks that execute ClickOnce application reference files (.appref-ms), indicating an attempt at persistence.
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

CrowdStrike has observed threat actors actively abusing Microsoft's ClickOnce technology for deploying malware, achieving persistence, and maintaining stealth. This abuse capitalizes on ClickOnce's user-friendly deployment process, which requires minimal user interaction and often flies under the radar of traditional security tools compared to executable files. Attackers convince targets to click on malicious links or `.application` files, bypassing typical email and endpoint defenses. The malicious payloads then execute within legitimate Microsoft process trees, such as `rundll32.exe` and `dfsvc.exe`, further evading detection. ClickOnce also provides a built-in update mechanism that attackers can leverage for maintaining remote access and dynamically changing command and control (C2) infrastructure. This technique allows for persistence by dropping `.appref-ms` files in startup folders or creating scheduled tasks, all without requiring elevated privileges.

## Attack Chain

1.  **Initial Access (User Execution)**: Threat actors convince a user to click a misleading button on a webpage or open a malicious `.application` file, leveraging the user-friendly nature of ClickOnce deployment.
2.  **Execution (Application Deployment)**: The user's action triggers the ClickOnce deployment process, which downloads and prepares the malicious application components.
3.  **Payload Execution**: The malicious payload is launched, executing within legitimate Microsoft process trees, specifically via `rundll32.exe` and `dfsvc.exe`, which are common for ClickOnce applications.
4.  **Defense Evasion (Stealthy Execution)**: The execution within trusted Microsoft processes helps the malicious activity blend in and evade scrutiny from security tools and users, who are accustomed to `.exe` files being monitored.
5.  **Persistence (Startup Folder)**: The adversary places a malicious `.appref-ms` application reference file in the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`), ensuring the payload runs on system boot.
6.  **Persistence (Scheduled Task)**: Alternatively, the attacker creates a scheduled task using `schtasks.exe` to regularly execute the `.appref-ms` file, establishing a more robust persistence mechanism.
7.  **Command and Control (Update Mechanism)**: The built-in ClickOnce update mechanism is utilized to fetch new components or updates from the attacker-controlled server, allowing for changes to C2 infrastructure, lateral movement, or additional payload delivery.

## Impact

The abuse of ClickOnce technology leads to successful malware deployment, persistent access, and command and control capabilities for threat actors. Organizations face significant risk due to the bypassing of common protection mechanisms like email filtering and traditional endpoint security, as the `.application` files often fly under the radar. Since ClickOnce applications do not require elevated privileges, attackers can compromise standard user accounts, which constitute the majority of enterprise endpoints. This results in unauthorized access, data exfiltration, or further network compromise, leading to financial loss, reputational damage, and operational disruption.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce persistence mechanisms.
*   Enable Sysmon file creation logging to activate rules detecting `.appref-ms` files in Startup folders.
*   Enable Sysmon process-creation logging to activate rules detecting `schtasks.exe` creating tasks that reference `.appref-ms` files.
*   Educate users on the risks associated with clicking on untrusted links and opening unexpected `.application` files, even if they appear to originate from legitimate sources.
