---
title: 'New Abuse of the ClickOnce Technology, Part 2: Stop Threat Actors from Clicking Once and Staying Forever'
slug: 2026-07-clickonce-abuse-part2
description: Threat actors are actively exploiting Microsoft's ClickOnce deployment technology, leveraging its low user interaction, lack of privilege requirements, and built-in update mechanisms to deliver malware, establish persistence, and maintain remote access, often executing payloads within legitimate rundll32.exe and dfsvc.exe processes.
date: "2026-07-08T08:07:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - persistence
  - delivery
  - windows
  - endpoint
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: To deploy a ClickOnce application, threat actors only need to convince their target to click once or twice to potentially get their malware executed and persist on the target system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Alternatively, ClickOnce applications can be deployed from .application files, which requires equally minimal user input and provides threat actors additional options to execute their payload.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persistence.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: By placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persistence.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses, move laterally, or take other actions.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence
    description: Detects the creation or modification of .appref-ms files in common auto-run or Start Menu locations, indicating potential ClickOnce persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Outbound Network Connection from ClickOnce Service
    description: Detects outbound network connections initiated by dfsvc.exe to non-private IP addresses, which could indicate C2 communication from a compromised ClickOnce application.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike has identified new methods of abusing Microsoft's ClickOnce deployment technology, which threat actors are actively leveraging to deliver malware, achieve persistence, and maintain remote access. This abuse exploits ClickOnce's minimal user interaction, ability to deploy without administrative privileges, and built-in updating mechanism. Actors are observed weaponizing `.application` files and manipulating `.appref-ms` shortcuts to stealthily execute payloads within legitimate Microsoft processes such as `rundll32.exe` and `dfsvc.exe`. The simplified delivery phase bypasses traditional defenses like email filters, and the lack of user awareness regarding ClickOnce installations contributes to the success of these attacks. This ongoing threat highlights a significant vector for initial access and long-term compromise against Windows endpoints.

## Attack Chain

1. **Initial Access:** Threat actor persuades a user to click a malicious link or button on a webpage, or directly delivers a weaponized `.application` file via a non-email vector.
2. **Execution (ClickOnce Deployment):** The malicious ClickOnce application is downloaded and executed, initiating the deployment process on the victim's machine.
3. **Execution (Payload Launch):** The malicious payload embedded within the ClickOnce application is launched, often executing discreetly within the context of legitimate Microsoft processes such as `rundll32.exe` or `dfsvc.exe`.
4. **Persistence (Shortcut Creation):** An `.appref-ms` file, configured to launch the malicious ClickOnce application, is created and placed in the user's Start Menu or other auto-run locations (e.g., Startup folder).
5. **Persistence (Update Mechanism Abuse):** The threat actor updates the malicious ClickOnce application on their controlled deployment server with new or modified malicious components, including altered command and control (C2) addresses.
6. **Persistence (Re-execution):** When the user subsequently launches the ClickOnce application from the Start Menu shortcut, the built-in update mechanism automatically downloads and executes the updated malicious payload without further user authorization.
7. **Command and Control:** The executed payload establishes command and control (C2) communications with the attacker's infrastructure, enabling remote access, further lateral movement, or data exfiltration.

## Impact

The successful exploitation of ClickOnce technology allows threat actors to bypass common security controls and establish persistent access to compromised systems without requiring administrative privileges. This can lead to the installation of various malware, including remote access tools, information stealers, or ransomware. Organizations face risks of data exfiltration, system takeover, and significant financial or reputational damage, as adversaries can continuously update their malicious applications and maintain a covert presence.

## Recommendation

* Enable Sysmon `FileCreate` and `ProcessCreate` event logging on Windows endpoints to capture activity related to ClickOnce deployment and execution.
* Deploy the Sigma rule "Detect ClickOnce .appref-ms Persistence" to identify suspicious creation or modification of `.appref-ms` files in auto-run directories.
* Deploy the Sigma rule "Detect Suspicious Outbound Network Connection from ClickOnce Service" to flag unusual network activity originating from the `dfsvc.exe` process.
* Educate users on the risks associated with clicking suspicious links and executing `.application` files from untrusted sources, emphasizing that these can trigger software installation.
