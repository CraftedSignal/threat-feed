---
title: Detection of IIS HTTP Logging Disabled via AppCmd.exe
slug: 2024-01-disable-iis-logging
description: This analytic detects the use of AppCmd.exe to disable HTTP logging on IIS servers, allowing adversaries to evade detection by removing evidence of their actions.
date: "2024-01-01T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - iis
  - logging
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - IIS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://www.crowdstrike.com/wp-content/uploads/2022/05/crowdstrike-iceapple-a-novel-internet-information-services-post-exploitation-framework-1.pdf
  - https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
  - https://www.secureworks.com/research/bronze-union
  - https://strontic.github.io/xcyclopedia/library/appcmd.exe-055B2B09409F980BF9B5A3969D01E5B2.html
rules:
  - title: Detect IIS HTTP Logging Disabled via AppCmd.exe
    description: Detects the execution of appcmd.exe to disable HTTP logging on IIS servers
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1505.004
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Detect IIS HTTP Logging Configuration Change via AppCmd.exe
    description: Detects the execution of appcmd.exe to modify HTTP logging configuration on IIS servers
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1505.004
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies the use of `AppCmd.exe` to disable HTTP logging on Internet Information Services (IIS) servers. The technique is significant as adversaries can use it to erase traces of their malicious activities. The detection focuses on process execution events logged by Endpoint Detection and Response (EDR) agents. By disabling HTTP logging, attackers can operate undetected, making it difficult to trace their actions and respond effectively to intrusions. The references indicate this technique has been observed in campaigns attributed to threat actors like OilRig, where IIS backdoors are used.

## Attack Chain

1.  Initial access to the system via exploitation of a vulnerability or compromised credentials.
2.  Attacker gains a foothold on the IIS server.
3.  The attacker executes `appcmd.exe` to modify IIS settings.
4.  `appcmd.exe` is executed with parameters to disable HTTP logging, such as `httplogging` or `dontlog:true`.
5.  The command modifies the IIS configuration, preventing HTTP request logs from being recorded.
6.  The attacker performs malicious actions on the compromised server (e.g., web shell deployment, data theft).
7.  With HTTP logging disabled, the attacker's activities are not recorded in standard IIS logs, hindering forensic analysis.
8.  The attacker maintains persistence and continues to exploit the compromised system.

## Impact

Successful execution of this attack can lead to a significant reduction in visibility into attacker activities on IIS servers. The lack of HTTP logs hinders incident response efforts, making it difficult to identify the scope and nature of the compromise. This could lead to prolonged attacker presence, further data exfiltration, or deployment of malicious software. This technique is a common step to evade defenses.

## Recommendation

*   Deploy the Sigma rule `Detect IIS HTTP Logging Disabled via AppCmd.exe` to your SIEM and tune for your environment.
*   Enable Sysmon process creation logging (Event ID 1) to capture command-line arguments of `appcmd.exe`.
*   Monitor process execution events for `appcmd.exe` with command-line arguments related to `httplogging` or `dontlog:true`.
*   Investigate any instances of `appcmd.exe` being executed by non-administrator accounts or unusual parent processes.
*   Review IIS configuration regularly for any unauthorized changes to HTTP logging settings.
