---
title: Account Discovery Command via SYSTEM Account
slug: 2024-01-09-system-account-discovery
description: The rule identifies when the SYSTEM account uses an account discovery utility, potentially indicating discovery activity after privilege escalation, focusing on utilities like whoami.exe and net1.exe executed under the SYSTEM account.
date: "2024-01-09T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - privilege-escalation
  - windows
vendors:
  - Microsoft
  - Dell
  - Obkio
  - SolarWinds
  - Infraon Corp
products:
  - Elastic Defend
  - Windows Defender Advanced Threat Protection
  - SupportAssistAgent
  - Obkio Agent
  - SolarWinds Agent
  - SecuraAgent
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_command_system_account.toml
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1078/003/
  - https://attack.mitre.org/tactics/TA0007/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Account Discovery via SYSTEM Account - whoami.exe
    description: Detects execution of whoami.exe by the SYSTEM account, indicating potential post-exploitation discovery activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1033
      - T1078.003
    data_sources:
      - process_creation
      - windows
  - title: Account Discovery via SYSTEM Account - net1.exe
    description: Detects execution of net1.exe by the SYSTEM account, excluding legitimate uses.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1078.003
      - T1087
    data_sources:
      - process_creation
      - windows
  - title: Account Discovery via SYSTEM Account - net1.exe without cmd.exe
    description: Detects execution of net1.exe by the SYSTEM account when not using cmd.exe, indicating potential post-exploitation discovery activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1078.003
      - T1087
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies instances where the SYSTEM account is used to execute account discovery utilities, such as `whoami.exe` and `net1.exe`. This behavior is commonly observed after an attacker has successfully achieved privilege escalation within a Windows environment, or after exploiting a web application. The rule is designed to detect post-exploitation discovery activity where an adversary attempts to gain situational awareness by enumerating accounts and system information using the elevated SYSTEM context. The rule leverages data from Elastic Defend and Sysmon Event ID 1 to identify these behaviors, helping defenders spot potential privilege escalation and lateral movement attempts. The original rule was created 2020/03/18 and updated 2026/05/04.

## Attack Chain

1. An attacker gains initial access to a system, potentially through exploiting a vulnerability in a web application or through phishing.
2. The attacker escalates privileges to the SYSTEM account, possibly by exploiting a local privilege escalation vulnerability.
3. The attacker executes `whoami.exe` or `net1.exe` via the SYSTEM account to enumerate user accounts and gather system information.
4. The `whoami.exe` or `net1.exe` process is spawned by a parent process such as a web server process (e.g., w3wp.exe) or a service process.
5. The attacker uses the discovered account information to plan further actions, such as lateral movement or credential theft.
6. The attacker may use `net1.exe` to query domain information.
7. The attacker leverages the gained information to identify valuable targets within the network.
8. The final objective is often data exfiltration, deployment of ransomware, or further compromise of the network.

## Impact

A successful attack can lead to unauthorized access to sensitive data, lateral movement within the network, and potential data exfiltration or ransomware deployment. Although this rule has low severity, the execution of discovery commands by the SYSTEM account can be a critical indicator of compromise. Early detection of such activity can prevent more severe damage.

## Recommendation

*   Deploy the provided Sigma rules to detect account discovery commands executed via the SYSTEM account and tune for your environment.
*   Enable Sysmon process creation logging (Event ID 1) to ensure the necessary data is available for detection.
*   Investigate any alerts generated by these rules, focusing on the process execution chain to identify the source of the SYSTEM account usage.
*   If the process tree includes a web-application server process, investigate suspicious file creation or modification to assess for webshell backdoors.
*   Review and harden web application security to prevent initial access and privilege escalation.
