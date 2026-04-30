---
title: Unusual Process Spawned by a Parent Process via Machine Learning
slug: 2024-01-unusual-process-spawn
description: A machine learning job detected a suspicious Windows process, predicted malicious by the ProblemChild model and flagged as an unusual child process name for its parent, potentially indicating LOLbins usage and evading traditional detection.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - lolbins
  - windows
  - machine-learning
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/problemchild
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
rules:
  - title: Suspicious Process Spawned by Common LOLBin
    description: Detects a rare process spawned by a common LOLBin like powershell.exe or cmd.exe. Relies on process creation events.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Rare Process Executed by WMI
    description: Detects execution of a rare process initiated via Windows Management Instrumentation (WMI).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This alert originates from an Elastic machine learning job named `problem_child_rare_process_by_parent_ea` designed to detect Living off the Land (LotL) attacks on Windows systems. The model identifies processes spawned by parent processes that are statistically rare and have a high probability of being malicious based on the "ProblemChild" supervised learning model. This approach aims to uncover malicious activities that utilize legitimate system binaries (LOLbins) for nefarious purposes, effectively bypassing traditional signature-based detections. The alert relies on Windows process events collected by Elastic Defend or Winlogbeat with the LotL Attack Detection integration. This detection method becomes particularly important as attackers increasingly rely on existing tools to blend in with normal system activity and avoid raising suspicion.

## Attack Chain

1.  Attacker gains initial access via unspecified means (e.g., phishing, compromised credentials).
2.  Attacker leverages a legitimate system binary (LOLbin) such as `powershell.exe` or `cmd.exe`.
3.  The LOLbin is used to execute a malicious payload or script.
4.  The malicious process is spawned as a child process of the LOLbin.
5.  Elastic's machine learning model identifies the child process as rare and potentially malicious based on its parent-child relationship and other features.
6.  The rare process executes malicious commands, possibly downloading further payloads.
7.  The attacker achieves their objective, such as data exfiltration or lateral movement.

## Impact

A successful attack utilizing LOLbins can lead to significant compromise, including data theft, system disruption, and further propagation within the network. The reliance on trusted system binaries makes these attacks difficult to detect with traditional methods, potentially allowing attackers to operate undetected for extended periods. The impact is directly correlated to the privileges of the initial compromised account and the effectiveness of lateral movement techniques employed by the attacker.

## Recommendation

*   Ensure that the Living off the Land (LotL) Attack Detection integration is installed and configured correctly, along with either Elastic Defend or Winlogbeat, as described in the rule's `setup` section.
*   Review the parent and child process names identified in the alert to determine if they are legitimate applications or associated with LOLbins, as detailed in the investigation guide within the rule's `note` section.
*   Investigate the command-line arguments used by the suspicious process for potentially malicious commands or scripts as described in the rule `note` section.
*   Tune the `anomaly_threshold` setting in the machine learning job configuration based on your environment's baseline activity to reduce false positives, as described in the rule documentation.
*   Implement exceptions for legitimate administrative tools and software updates to reduce false positives, as mentioned in the rule's `note` section.
