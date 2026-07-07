---
title: Threat Actors Abuse Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are actively leveraging legitimate Microsoft ClickOnce technology to bypass traditional defenses, gain initial access, execute malware, and establish persistence on Windows systems through minimal user interaction with deceptive application files and malicious updates.
date: "2026-07-07T08:34:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - initial-access
  - defense-evasion
  - malware
vendors:
  - Microsoft
products:
  - ClickOnce
  - Windows
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: For instance, by placing a .appref-ms file in the Startup folder or creating a scheduled task to process the file regularly, they can ensure persist
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe), increasing the stealthiness of the execution. Further, the UI displayed to the user is a legitimate one from Microsoft.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: The malicious payload executes within legitimate Microsoft process trees (with rundll32.exe and dfsvc.exe)
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This means that every time a user starts the ClickOnce application from the Start Menu, whoever controls the server can update the app. This gives threat actors a reliable method for maintaining remote access and updating their malware as needed to change command and control (C2) addresses
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects the creation or modification of a ClickOnce application reference file (.appref-ms) in a user's Startup folder, which is a known method for establishing persistence by threat actors.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task Creation
    description: Detects the creation of a scheduled task that executes a ClickOnce application reference file (.appref-ms), a technique used by attackers for persistence.
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

Threat actors are increasingly abusing Microsoft's ClickOnce deployment technology to facilitate initial access and maintain persistence on target systems, as detailed by CrowdStrike. This technique, observed in recent campaigns, exploits the user-friendly nature of ClickOnce, which requires minimal user interaction (often just one or two clicks) to install applications. Adversaries deliver malicious payloads by convincing users to click deceptive buttons on webpages or execute `.application` files. This approach frequently bypasses conventional security mechanisms, such as email filtering and executable file scrutiny, due to a general lack of awareness around ClickOnce applications. Unlike traditional `.msi` installations, ClickOnce apps do not require administrative privileges, significantly lowering the barrier to entry for attackers. Furthermore, the built-in update mechanism of ClickOnce allows attackers to maintain remote access and update their malware, often executing stealthily within legitimate Microsoft process trees like `rundll32.exe` and `dfsvc.exe`.

## Attack Chain

1.  Attacker crafts and delivers a malicious ClickOnce application, often disguised as a legitimate tool, via deceptive links on phishing pages or as `.application` files in spearphishing attempts.
2.  The target user is enticed to click a button on a webpage or execute the provided `.application` file, initiating the ClickOnce deployment process.
3.  Legitimate Microsoft ClickOnce components, such as `dfsvc.exe` (the .NET Framework Deployment Service), are invoked to download and initiate the application installation.
4.  The malicious payload embedded within the ClickOnce application is executed on the victim's system, operating under the context of legitimate Microsoft processes like `rundll32.exe` or `dfsvc.exe`.
5.  The attacker establishes persistence by strategically dropping an `.appref-ms` application reference file into the user's Windows Startup folder.
6.  Alternatively, persistence is achieved by creating a new scheduled task that is configured to regularly execute the malicious `.appref-ms` file.
7.  The attacker leverages the ClickOnce application's legitimate update mechanism to deliver new malicious components, change command and control (C2) infrastructure, or deploy additional malware without further user interaction.
8.  The compromised system is then used for remote access, data exfiltration, lateral movement, or other post-exploitation activities, maintaining a covert presence due to the legitimate process execution.

## Impact

The exploitation of ClickOnce technology allows threat actors to successfully bypass common security defenses, resulting in unauthorized initial access and persistent presence on targeted systems. By circumventing traditional malware scrutiny and requiring only standard user privileges, attackers can compromise a broader range of endpoints. If successful, these attacks lead to the stealthy execution of malware, enabling remote access, potential data exfiltration, and the establishment of command and control channels. The ability to update malware via the legitimate ClickOnce update mechanism ensures long-term compromise and adaptability, posing a significant risk of sustained compromise and further exploitation within an organization's network.

## Recommendation

*   Enable Sysmon `ProcessCreate`, `FileCreate`, `RegistryEvent` and `CreateRemoteThread` logging to gather essential telemetry for the detection rules below.
*   Deploy the Sigma rules provided in this brief to your SIEM and tune them for your environment, paying close attention to `TargetFilename|endswith: ".appref-ms"` in startup folders and `schtasks.exe` command lines.
*   Review network egress logs for suspicious connections originating from processes like `dfsvc.exe` or `rundll32.exe` to unknown or untrusted external IP addresses and domains.
*   Implement application whitelisting or strict software restriction policies to prevent unauthorized ClickOnce applications from running, especially from untrusted sources.
