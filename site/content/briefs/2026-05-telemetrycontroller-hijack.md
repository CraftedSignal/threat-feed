---
title: TelemetryController Scheduled Task Hijack for Persistence
slug: 2026-05-telemetrycontroller-hijack
description: The rule detects the hijack of the Microsoft Compatibility Appraiser scheduled task to establish persistence with system integrity level, by monitoring CompatTelRunner.exe process execution and detecting unexpected child processes.
date: "2026-05-12T18:41:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - scheduled_task
  - telemetry
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Compatibility Appraiser
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_via_telemetrycontroller_scheduledtask_hijack.toml
rules:
  - title: Detect Persistence via TelemetryController Scheduled Task Hijack
    description: Detects the execution of unexpected processes spawned by CompatTelRunner.exe using the -cv flag, indicating a potential TelemetryController hijack.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.002
    data_sources:
      - process_creation
      - windows
  - title: Detect TelemetryController Registry Modification
    description: Detects modification of TelemetryController registry keys, which could indicate a persistence attempt.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This rule detects a persistence technique that abuses the Microsoft Compatibility Appraiser scheduled task (CompatTelRunner.exe) to execute arbitrary code with SYSTEM privileges. Attackers can hijack this task by modifying registry values associated with the TelemetryController, causing CompatTelRunner.exe to launch malicious executables. This allows for a persistent presence on the system, bypassing traditional security measures by leveraging a legitimate Windows component. The attack relies on manipulating the expected behavior of the telemetry service to execute attacker-controlled code with elevated privileges. Detection focuses on identifying child processes of CompatTelRunner.exe that are not standard Windows utilities, indicating a potential compromise. This technique is significant because it enables attackers to maintain persistence even after system reboots, and the use of a trusted process makes it harder to detect.

## Attack Chain

1. An attacker gains initial access to the system, potentially through phishing or exploiting a software vulnerability.
2. The attacker modifies registry keys under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController` to point to a malicious executable or script.
3. The Microsoft Compatibility Appraiser scheduled task (CompatTelRunner.exe) is triggered, either manually or through its regular schedule.
4. CompatTelRunner.exe, due to the modified registry values, launches the attacker-controlled executable with SYSTEM privileges using the `-cv` flag to pass control.
5. The malicious executable executes, performing actions such as installing malware, establishing a reverse shell, or exfiltrating sensitive data.
6. The attacker may further modify the system to ensure the malicious executable is launched persistently.
7. The attacker leverages the elevated privileges gained to perform lateral movement or other malicious activities on the network.

## Impact

A successful attack allows the threat actor to establish persistent access to the compromised system with SYSTEM privileges. This can lead to a wide range of malicious activities, including data theft, installation of ransomware, or using the compromised system as a foothold for further attacks within the network. The high integrity level of the hijacked process grants the attacker significant control over the system.

## Recommendation

*   Enable Sysmon process creation logging to capture `event.type == "start"` and `process.parent.name : "CompatTelRunner.exe"` to enable the rules below.
*   Deploy the Sigma rule "Persistence via TelemetryController Scheduled Task Hijack" to your SIEM and tune for your environment to detect unexpected child processes of CompatTelRunner.exe.
*   Monitor registry modifications to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController` to detect unauthorized changes to telemetry settings.
*   Investigate any processes launched by CompatTelRunner.exe with command-line arguments containing `-cv` that are not standard Windows utilities.
