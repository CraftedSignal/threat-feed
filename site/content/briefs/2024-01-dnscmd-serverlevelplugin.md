---
title: Abuse of dnscmd.exe to Modify DNS ServerLevelPluginDLL
slug: 2024-01-dnscmd-serverlevelplugin
description: Attackers can use dnscmd.exe with administrative privileges to configure the Microsoft DNS ServerLevelPluginDll setting, allowing them to load arbitrary DLLs and execute code within the DNS service context for persistence and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows Server
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd
rules:
  - title: Detect Dnscmd Usage to Configure ServerLevelPluginDLL
    description: Detects command-line usage of dnscmd.exe to configure the Microsoft DNS ServerLevelPluginDll setting.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1574
    data_sources:
      - process_creation
      - windows
  - title: Detect Dnscmd Setting ServerLevelPluginDLL via Windows Event Log
    description: Detects command-line usage of dnscmd.exe to configure the Microsoft DNS ServerLevelPluginDll setting using Windows Event Log 4688.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1574
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft DNS ServerLevelPluginDll setting allows the DNS service to load arbitrary DLLs. An attacker with DNS administrative privileges can abuse `dnscmd.exe` to modify this setting and load a malicious DLL. This grants the attacker code execution in the context of the DNS service. This technique can be leveraged for persistence, privilege escalation, and even domain compromise. The abuse of this setting is particularly concerning because the DNS service often runs with elevated privileges, making it a highly desirable target for attackers. This technique has been observed in the wild and documented publicly, highlighting its potential for real-world impact. Defenders should monitor for unauthorized modifications to the ServerLevelPluginDll setting via `dnscmd.exe` to mitigate this threat.

## Attack Chain

1. An attacker gains initial access through existing compromises or leveraging exploits.
2. The attacker escalates privileges to obtain DNS administrative rights.
3. The attacker executes `dnscmd.exe` with the `/config` and `/serverlevelplugindll` parameters to set a malicious DLL.
4. The DNS service loads the attacker-controlled DLL.
5. The malicious DLL executes arbitrary code within the context of the DNS service.
6. The attacker achieves persistence by ensuring the malicious DLL is loaded on each DNS service restart.
7. The attacker leverages the elevated privileges of the DNS service to perform actions such as lateral movement or data exfiltration.

## Impact

Successful exploitation allows attackers to execute arbitrary code within the highly privileged context of the Windows DNS Server service. This can lead to complete domain compromise, allowing the attacker to control critical network infrastructure. The impact can range from data theft and service disruption to complete takeover of the Active Directory environment. The number of potential victims is significant, encompassing any organization running Windows DNS Server.

## Recommendation

*   Monitor process execution for `dnscmd.exe` with command-line arguments containing `/config` and `/serverlevelplugindll` using the provided Sigma rule.
*   Enable Sysmon Event ID 1 and Windows Event Log Security 4688 to capture process creation events.
*   Investigate any instances of `dnscmd.exe` modifying the ServerLevelPluginDll setting.
*   Implement strict access controls to limit who can administer the DNS service.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
