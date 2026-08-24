---
title: Detection of Ping-Based Execution Delays in Batch Scripts
slug: 2026-08-ping-sleep-batch
description: Adversaries frequently utilize the ping command as a stealthy sleep mechanism to introduce execution delays, aiming to bypass automated sandboxing and dynamic analysis by chaining commands with operators.
date: "2026-08-24T15:46:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - sandbox-evasion
  - batch-scripting
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497
    technique_name: Virtualization/Sandbox Evasion
    evidence: Adversaries may use ping as an alternative to explicit sleep or timeout commands to introduce execution delays, potentially evading automated analysis, sandboxing, or behavior-based detection.
    confidence_band: high
rules:
  - title: Detect Ping Command Used as Sleep Mechanism
    description: Detects the use of ping with a count flag combined with shell separators to induce execution delays, commonly used for sandbox evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1497.003
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
    - action: Deploy Sigma rule to endpoint monitoring platform
      owner: Detection Engineering
      due: 48h
      evidence: Need to detect sandbox evasion techniques
  hunt_leads:
    - lead: Search for ping.exe command lines containing '&', '||', or '>', and '-n'
      technique_id: T1497.003
      data_needed:
        - Process creation event logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source analytic search logic
---

Adversaries often use the standard Windows 'ping' utility as an improvised delay mechanism to introduce pauses in command-line execution sequences. By leveraging the '-n' (count) flag, attackers can force a delay proportional to the number of ICMP echo requests sent, effectively creating a 'sleep' command without relying on standard system utilities that might be more heavily monitored. This technique is frequently employed during the initial staging or persistence phases of an attack to evade automated sandbox analysis, dynamic analysis, or behavior-based detection logic.

Threat actors chain these ping-based delays with subsequent malicious commands using Windows batch command separators such as '&', '||', or redirection operators ('>'). This methodology has been observed in various campaigns, including those involving data destruction malware like WhisperGate, as well as multiple Remote Access Trojans (RATs) and ransomware families. Defenders must analyze the full command-line context, parent process, and user activity to differentiate this malicious usage from legitimate network troubleshooting or administrative scripting.

## Impact

Successful implementation of this technique allows adversaries to bypass time-limited sandbox environments, increasing the likelihood that malicious payloads will execute successfully on target hosts. This pattern has been associated with destructive malware, ransomware, and information-stealing campaigns, where undetected execution can lead to full system compromise, data encryption, or credential theft.

## Recommendation

- Implement EDR process-creation telemetry monitoring for ping.exe command lines that include both count flags and command separators.
- Deploy the provided Sigma rule to identify suspicious command chaining patterns at the endpoint level.
- Establish a baseline of legitimate administrative scripts using ping for network testing to minimize false positives during tuning.
- Prioritize investigation of alerts where ping-based delays precede suspicious activities like credential dumping, lateral movement tools, or file system modifications.
