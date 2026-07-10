---
title: Windows Time-Based Evasion via Ping Delay
slug: 2024-01-time-based-evasion
description: This analytic detects potentially malicious processes initiating a ping delay using an invalid IP address, a tactic used by malware like NJRAT to evade detection by delaying actions.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - NJRAT
tags:
  - time-based-evasion
  - njrat
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497
    technique_name: Virtualization/Sandbox Evasion
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat
rules:
  - title: Detect Windows Time Based Evasion via Ping Delay
    description: Detects processes using ping to create delays, an evasion tactic used by malware like NJRAT.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1497.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Parent Process Executing Ping Delay
    description: Detects parent processes that initiate ping delays, commonly used for evasion by malware such as NJRAT
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1497.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying a specific time-based evasion technique employed by malware, including NJRAT. The technique involves initiating a ping command to an invalid IP address ("ping 0 -n"), which introduces a delay. This delay can be used to evade detection by security tools or to postpone malicious actions, such as self-deletion, until a later time. This behavior is typically observed on Windows endpoints and leverages the native `ping.exe` utility. The detection logic analyzes endpoint telemetry for command-line executions matching this pattern. Identifying and responding to this activity is crucial, as it indicates a potential attempt to evade security controls and maintain a persistent presence within the compromised environment. The timeframe for this technique has been observed since NJRAT's emergence and continues to be relevant as an evasion tactic.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., via phishing or exploit).
2.  Malware (e.g., NJRAT) is deployed on the compromised endpoint.
3.  The malware executes `ping.exe` with the argument `ping 0 -n <seconds>`.
4.  The `ping` command attempts to resolve the invalid IP address, causing a delay.
5.  During the delay, the malware may perform other malicious activities, such as collecting system information or establishing persistence.
6.  After the delay, the malware continues its primary objective, which may include data exfiltration, remote control, or self-deletion.
7.  The self-deletion is delayed through ping, so that security tools won't notice the malicious program present on the host.

## Impact

A successful attack using time-based evasion can allow malware to remain undetected for a longer period. This can lead to increased data exfiltration, prolonged remote access, and greater damage to the compromised system. Time-based evasion is a common technique among malware, potentially affecting a broad range of organizations. The impact includes increased dwell time for attackers, which gives them more opportunities to compromise sensitive data and systems. If successful, this evasion can lead to the deployment of ransomware or other destructive payloads.

## Recommendation

*   Deploy the Sigma rule `Detect Windows Time Based Evasion via Ping Delay` to identify processes executing the `ping 0 -n` command.
*   Investigate any identified instances of `ping.exe` with the `0 -n` argument to determine if it is associated with malicious activity.
*   Enable Sysmon process creation logging (Event ID 1) to capture the necessary command-line information for the detection.
*   Ensure that endpoint detection and response (EDR) agents are configured to collect and forward process execution data.
*   Review `https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat` for more information about NJRAT and its tactics.
