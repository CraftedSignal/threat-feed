---
title: Suspicious Child Processes from Communication Applications
slug: 2024-01-suspicious-comm-app-child-process
description: The detection rule identifies suspicious child processes spawned from communication applications on Windows systems, potentially indicating masquerading or exploitation of vulnerabilities within these applications.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - windows
vendors:
  - Elastic
  - SentinelOne
  - Microsoft
  - Google
  - Mozilla
  - Opera
  - Cisco
  - Discord
  - WhatsApp
  - Zoom
  - Brave
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Microsoft Teams
  - Google Chrome
  - Mozilla Firefox
  - Opera
  - Cisco WebEx
  - Discord
  - WhatsApp
  - Zoom
  - Brave Browser
  - Slack
  - thunderbird.exe
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_communication_apps_suspicious_child_process.toml
rules:
  - title: Suspicious Communication App Child Process - PowerShell
    description: Detects PowerShell processes spawned by communication applications, which may indicate exploitation or masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Communication App Child Process - CMD
    description: Detects command prompt processes spawned by communication applications, which may indicate exploitation or masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Communication App Child Process - Non-Standard Executable Location
    description: Detects child processes spawned by communication applications from non-standard executable locations, potentially indicating malware execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule focuses on identifying suspicious child processes of communication applications such as Slack, Cisco Webex, Microsoft Teams, Discord, WhatsApp, Zoom, and Thunderbird on Windows operating systems. Attackers may attempt to masquerade as legitimate processes or exploit vulnerabilities in these applications to execute malicious code. The rule monitors for the creation of child processes by these communication apps and checks if those child processes are unexpected, untrusted, or lack a valid code signature. This detection is crucial because successful exploitation can lead to unauthorized access, data exfiltration, or further compromise of the system. The rule has been actively maintained since August 2023, with updates as recent as May 2026, indicating its relevance and ongoing refinement to address emerging threats.

## Attack Chain

1.  User launches a communication application (e.g., Slack, Teams, Webex).
2.  The communication application executes a vulnerable or compromised component.
3.  The compromised component spawns a child process (e.g., powershell.exe, cmd.exe).
4.  The child process executes a malicious command or script.
5.  The script attempts to download additional payloads from an external source.
6.  The payload executes, establishing persistence through registry modification or scheduled tasks.
7.  The attacker gains remote access to the system.
8.  Data exfiltration or lateral movement within the network occurs.

## Impact

A successful attack can lead to the compromise of sensitive data, installation of malware, and potential lateral movement within the organization's network. By exploiting communication applications, attackers can gain access to internal communications, confidential documents, and user credentials. The number of affected users and the extent of the damage depend on the compromised application and the attacker's objectives. If successful, this attack may lead to significant financial loss, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule `Suspicious Communication App Child Process` to your SIEM to detect anomalous child processes spawned by communication applications and tune for your environment.
*   Enable process creation logging with command line arguments in Windows to ensure that the Sigma rule has the necessary data to function correctly (logsource: `process_creation`, product: `windows`).
*   Investigate any alerts generated by the rule and review the command line arguments of the spawned processes to identify potential malicious activity.
*   Implement application whitelisting to restrict the execution of unauthorized applications and reduce the attack surface.
*   Ensure that all communication applications are updated to the latest versions to patch known vulnerabilities and reduce the risk of exploitation.
*   Examine the network activity of the affected system to identify any suspicious outbound connections that may indicate data exfiltration or communication with a command and control server, referencing the setup guide.
