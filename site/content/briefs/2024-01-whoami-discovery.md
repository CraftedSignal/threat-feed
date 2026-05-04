---
title: Suspicious Whoami Process Activity
slug: 2024-01-whoami-discovery
description: This rule detects suspicious use of whoami.exe to display user, group, and privileges information for the user who is currently logged on to the local system, potentially indicating post-compromise discovery activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - windows
  - threat-detection
vendors:
  - Microsoft
  - Cohesity
products:
  - Microsoft Monitoring Agent
  - Cohesity Windows Agent
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1069/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_whoami_command_activity.toml
rules:
  - title: Whoami Process Activity - System Account
    description: Detects the execution of whoami.exe by system accounts which is often indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
  - title: Whoami Process Activity - Suspicious Parent Process
    description: Detects the execution of whoami.exe with suspicious parent processes like wsmprovhost.exe, w3wp.exe, wmiprvse.exe, rundll32.exe, or regsvr32.exe.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `whoami` utility is commonly used by attackers post-compromise to gather information about the current user and their privileges on a compromised system. This information helps attackers assess their level of access and plan further actions within the environment, such as privilege escalation or lateral movement. This activity is most concerning when executed by SYSTEM accounts or from unusual parent processes. This detection identifies unusual or suspicious executions of `whoami.exe`, especially when associated with system privileges or specific parent processes known to be abused by attackers. The rule is designed to function across various Windows environments and considers potential false positives from legitimate administrative tools.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the Windows system through an exploit or compromised credentials.
2.  Privilege Escalation (Optional): The attacker may attempt to elevate privileges to a higher level, potentially SYSTEM.
3.  Discovery: The attacker executes `whoami.exe` to determine the current user and their privileges.
4.  Information Gathering: The attacker analyzes the output of `whoami.exe` to understand the context of the compromised system.
5.  Lateral Movement (Conditional): Based on the information gathered, the attacker may attempt to move laterally to other systems.
6.  Further Exploitation: The attacker leverages the gathered information to further exploit the compromised system or network.
7.  Persistence (Optional): The attacker may establish persistence to maintain access to the compromised system.
8.  Objective Completion: The attacker achieves their final objective, such as data exfiltration or system disruption.

## Impact

Successful exploitation and reconnaissance can allow attackers to gain a deeper understanding of a compromised system. This may lead to further exploitation, lateral movement, and ultimately, the exfiltration of sensitive data or the disruption of critical services. While the `whoami` command itself is not inherently malicious, its suspicious usage often indicates malicious activity within a compromised environment. The severity is low because the execution of whoami by itself is not enough to confirm malicious activity, and further investigation is needed.

## Recommendation

*   Enable process creation logging with command line arguments to detect `whoami.exe` executions (reference: logs-endpoint.events.process-\*, logs-system.security\*, logs-windows.forwarded\*, logs-windows.sysmon_operational-\*).
*   Deploy the Sigma rule "Whoami Process Activity" to your SIEM and tune for your environment (reference: rule).
*   Investigate parent processes of `whoami.exe` for any suspicious or unusual activity (reference: Attack Chain).
*   Monitor for other discovery commands executed around the same time as `whoami.exe` (reference: Related rules).
*   Review and tune the false positives outlined in the rule to minimize noise (reference: false_positives).
