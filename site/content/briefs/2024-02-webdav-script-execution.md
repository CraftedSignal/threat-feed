---
title: Suspicious Execution of Windows Scripts from WebDAV Share
slug: 2024-02-webdav-script-execution
description: Adversaries may execute Windows scripts directly from a remote WebDAV share to evade detection and avoid writing malicious files to disk; this activity is detected by monitoring process command lines for suspicious WebDAV paths.
date: "2024-02-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webdav
  - script-execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
references:
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/002/
  - https://attack.mitre.org/techniques/T1570/
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/techniques/T1071/001/
  - https://attack.mitre.org/techniques/T1105/
rules:
  - title: Detect Suspicious Execution from a WebDav Share
    description: Detects attempts to execute Windows scripts from a remote WebDav Share.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1105
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Conhost Spawning from WebDav Path
    description: Detects conhost.exe spawning with parent process originating from a WebDav Share, indicating potential script execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly leveraging WebDAV (Web Distributed Authoring and Versioning) shares to host and execute malicious scripts directly in memory, bypassing traditional file-based detection mechanisms. This technique allows them to avoid dropping suspicious files onto the victim's file system, thus reducing the likelihood of detection by endpoint security solutions. Observed activity involves executing scripting engines like PowerShell, cmd.exe, or wscript.exe with command-line arguments pointing to scripts hosted on remote WebDAV shares. Defenders should monitor process command lines for known WebDAV path patterns and unusual process execution from these locations to identify and mitigate potential threats. The scope of targeting is broad, affecting any Windows environment where users might access external WebDAV resources.

## Attack Chain

1. The attacker compromises a user's credentials or leverages an existing vulnerability to gain initial access.
2. The attacker sets up a WebDAV server to host malicious scripts (e.g., PowerShell scripts, batch files).
3. The attacker sends a phishing email or uses another social engineering tactic to trick the user into executing a command.
4. The user executes a command using cmd.exe, powershell.exe, wscript.exe, or mshta.exe.
5. The command line contains a path to a script hosted on a remote WebDAV share (e.g., `\\webdav.example.com\script.ps1`).
6. The scripting engine downloads and executes the script directly from the WebDAV share without writing it to disk.
7. The script performs malicious actions, such as downloading additional payloads, establishing persistence, or exfiltrating data.
8. The attacker achieves their objective, such as data theft, system compromise, or lateral movement within the network.

## Impact

Successful exploitation can lead to complete system compromise, data theft, and further propagation within the network. Organizations may experience data breaches, financial losses, and reputational damage. If successful, attackers gain a foothold in the network without writing malicious files to disk which makes it harder for traditional AV to detect the activity.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious Execution from a WebDav Share" to your SIEM and tune for your environment to detect script execution from WebDAV shares.
*   Monitor process creation events, specifically looking for cmd.exe, powershell.exe, wscript.exe, mshta.exe executing with command lines containing "*\\webdav\\*", "*\\DavWWWRoot\\*", "*\\\\*.*@8080\\*", "*\\\\*.*@80\\*", "*\\\\*.*@8443\\*", "*\\\\*.*@443\\*" as described in the rule and overview.
*   Review and restrict the usage of WebDAV shares within the organization, especially external shares.
*   Implement application control policies to restrict the execution of unsigned or untrusted scripts.
*   Enable Sysmon process creation logging to capture detailed information about process executions and command-line arguments.
