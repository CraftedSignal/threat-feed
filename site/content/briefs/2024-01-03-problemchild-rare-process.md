---
title: ProblemChild ML Model Detects Unusual Process on Windows Host
slug: 2024-01-03-problemchild-rare-process
description: The ProblemChild machine learning model detected a rare Windows process indicative of defense evasion, potentially involving LOLbins, on a host not commonly associated with malicious activity.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - lolbin
  - windows
  - machine-learning
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/problemchild
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Suspicious Process Execution via LOLbins
    description: Detects the execution of suspicious processes via Living off the Land binaries (LOLbins)
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSHTA Execution
    description: Detects suspicious execution of MSHTA
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection leverages the ProblemChild supervised machine learning model to identify unusual Windows processes that may be indicative of defense evasion tactics. The model flags processes that are both statistically unusual for a given host and predicted to be suspicious based on their characteristics. This approach aims to detect Living off the Land (LotL) attacks, where adversaries use legitimate system binaries (LOLbins) to evade traditional signature-based detection methods. The rule specifically targets processes observed on hosts that do not commonly exhibit malicious behavior. The alert requires the Elastic's Living off the Land (LotL) Attack Detection integration assets to be installed, processing Windows process events collected by Elastic Defend or Winlogbeat. This detection rule was last updated on 2026-04-01 and requires Elastic Stack version 9.4.0 or higher.

## Attack Chain

1.  Adversary gains initial access to a Windows system.
2.  The attacker leverages a LOLbin (e.g., `powershell.exe`, `cmd.exe`, `mshta.exe`) to execute malicious commands.
3.  The LOLbin spawns a child process to perform a specific task, such as downloading a file or modifying system settings.
4.  The spawned process exhibits characteristics flagged as suspicious by the ProblemChild ML model.
5.  The suspicious process attempts to evade detection by masquerading as a legitimate system process or by obfuscating its activity.
6.  The attacker uses the process to establish persistence, escalate privileges, or move laterally within the network.
7.  The ultimate objective is to exfiltrate sensitive data, deploy ransomware, or disrupt business operations.

## Impact

A successful defense evasion attack can allow adversaries to operate undetected within a network, leading to data breaches, financial losses, and reputational damage. The use of LOLbins makes it difficult to distinguish malicious activity from legitimate system operations. This detection rule aims to reduce the dwell time of attackers by identifying suspicious processes early in the attack chain, even if they are using legitimate tools. False positives may occur due to routine administrative tasks, software updates, or custom scripts.

## Recommendation

*   Ensure that the Living off the Land (LotL) Attack Detection integration is installed and properly configured, as described in the "Setup" section of this brief.
*   Verify that Windows process events are being collected by Elastic Defend or Winlogbeat, as required by the detection rule.
*   Deploy the following Sigma rule to detect unusual process spawns and tune the `Image|endswith` and `CommandLine|contains` conditions for your specific environment.
*   Review the investigation guide provided in the rule description to triage and analyze potential false positives.
*   Adjust the `anomaly_threshold` (currently 75) in the Elastic detection rule based on your environment's baseline to reduce noise.
*   Monitor for MITRE ATT&CK Technique T1218 (System Binary Proxy Execution) to identify potential LOLbin abuse.
