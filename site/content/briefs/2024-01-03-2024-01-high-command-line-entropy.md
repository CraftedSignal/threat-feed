---
title: High Command Line Entropy Detected for Privileged Commands on Linux
slug: 2024-01-high-command-line-entropy
description: A machine learning job has identified an unusually high median command line entropy for privileged commands executed by a user on Linux systems, suggesting possible privileged access activity through command lines, indicating potential obfuscation or unauthorized use of privileged access.
date: "2024-01-03T15:30:00Z"
severities:
  - low
tags:
  - privileged-access-detection
  - machine-learning
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Suspicious High Entropy Command Line - Potential Obfuscation
    description: Detects command lines with high entropy, which may indicate obfuscation techniques used by attackers to evade detection. This rule analyzes the Shannon entropy of command-line strings to identify potentially malicious commands.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
  - title: Privileged Command Execution with Obfuscation (Sysmon Linux)
    description: Detects the execution of privileged commands (e.g., sudo, su) with command line arguments exhibiting high entropy, indicative of potential obfuscation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1027
      - T1078
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This alert originates from a machine learning job designed to detect anomalous command-line activity on Linux systems. Specifically, it focuses on identifying instances where privileged commands are executed with unusually high entropy. High entropy in command lines often signifies obfuscation, which threat actors use to mask their activities and evade detection. This rule leverages the Privileged Access Detection (PAD) integration from Elastic to identify these anomalies. The PAD integration…
