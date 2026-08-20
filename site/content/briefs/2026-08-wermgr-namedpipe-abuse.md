---
title: Abuse of wermgr.exe for Named Pipe Communication
slug: 2026-08-wermgr-namedpipe-abuse
description: Malware families like Qakbot and Trickbot inject malicious code into the legitimate Windows Error Reporting process (wermgr.exe) to establish covert named pipe communication for C2 and persistence.
date: "2026-08-20T19:06:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This activity is significant because wermgr.exe, a legitimate Windows OS Problem Reporting application, is often abused by malware such as Trickbot and Qakbot to execute malicious code.
    confidence_band: high
rules:
  - title: Detect Suspicious wermgr.exe Named Pipe Activity
    description: Detects the wermgr.exe process creating or connecting to a named pipe, which is a common technique used by malware like Qakbot to facilitate covert communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for wermgr.exe named pipe activity
      owner: Detection Engineering
      due: 24h
      evidence: Source explicitly identifies this as an anomaly detection candidate
  mitigation_plan:
    - priority: medium_term
      action: Review process injection protections and EDR/Sysmon coverage
      owner: IT Operations
      addresses: T1071
      evidence: Injected wermgr.exe processes indicate successful bypassing of standard endpoint protections
---

The wermgr.exe process, which is the legitimate Windows Error Reporting application, is frequently targeted by sophisticated malware families including Qakbot and Trickbot. Because wermgr.exe is a trusted system binary, threat actors use process injection techniques to execute malicious code within its memory space. A primary goal of this injection is to facilitate covert inter-process communication using Windows named pipes. This allows the injected code to bypass standard monitoring or establish persistent command-and-control channels without immediately triggering process-based alerts associated with unknown binaries. Detection of wermgr.exe creating or connecting to named pipes is a highly reliable indicator of malicious activity, as the process does not typically require this capability for its intended reporting function.

## Impact

Successful exploitation allows attackers to maintain stealthy persistence and facilitate command-and-control communication within a compromised Windows environment. By masking malicious traffic behind the Windows Error Reporting process, attackers can complicate host-based forensics and evade standard security controls, potentially leading to unauthorized privilege escalation or lateral movement.

## Recommendation

Deploy the provided Sigma rule to monitor for anomalous named pipe activity originating from wermgr.exe on all Windows endpoints. Ensure Sysmon Event ID 17 (Pipe Created) and 18 (Pipe Connected) are enabled to provide the necessary telemetry for this detection. When an alert fires, prioritize investigating the process lineage of wermgr.exe to identify the source of the initial injection.
