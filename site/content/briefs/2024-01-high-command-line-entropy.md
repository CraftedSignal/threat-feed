---
title: High Command Line Entropy Detected for Privileged Commands on Linux
slug: 2024-01-high-command-line-entropy
description: A machine learning job has identified an unusually high median command line entropy for privileged commands executed by a user on Linux systems, suggesting possible privileged access activity through command lines, indicating potential obfuscation or unauthorized use of privileged access.
date: "2024-01-03T15:30:00Z"
type: advisory
types:
  - advisory
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

This alert originates from a machine learning job designed to detect anomalous command-line activity on Linux systems. Specifically, it focuses on identifying instances where privileged commands are executed with unusually high entropy. High entropy in command lines often signifies obfuscation, which threat actors use to mask their activities and evade detection. This rule leverages the Privileged Access Detection (PAD) integration from Elastic to identify these anomalies. The PAD integration requires Linux logs collected by Elastic Defend or Sysmon Linux. The detection logic analyzes command lines associated with privileged commands, flagging those with a high degree of randomness or complexity. This can indicate unauthorized use of valid accounts (T1078) or attempts at privilege escalation, especially if combined with defense evasion techniques (T1027) such as obfuscating commands. The rule and associated ML job have been in production since Feb 2025 and require Elastic Stack version 9.4.0 or higher.

## Attack Chain

1. An attacker gains initial access to a Linux system, potentially through a compromised account or vulnerability exploitation.
2. The attacker identifies privileged commands they need to execute to achieve their objectives, such as gaining root access or modifying sensitive files.
3. To evade detection, the attacker obfuscates their commands using techniques like encoding, compression, or complex string manipulation.
4. The attacker executes the obfuscated privileged commands via the command line.
5. Elastic Defend or Sysmon Linux captures the command-line activity and logs it to Elasticsearch.
6. The Privileged Access Detection ML job analyzes the command lines and calculates their entropy.
7. If the entropy exceeds a predefined threshold, the ML job flags the activity as anomalous and generates an alert.
8. Security analysts investigate the alert to determine the nature of the suspicious activity and take appropriate action.

## Impact

A successful privilege escalation can grant an attacker complete control over a Linux system, allowing them to steal sensitive data, install malware, or disrupt critical services. While this rule itself triggers on unusual command line activity, the underlying behavior could lead to a full system compromise. The number of potential victims is directly related to the scope of the Linux environment being monitored. Sectors commonly targeted by privilege escalation attacks include technology, finance, and government.

## Recommendation

*   Deploy the Privileged Access Detection integration and ensure that Linux logs from Elastic Defend or Sysmon Linux are being ingested (Setup section).
*   Review and tune the machine learning job `pad_linux_high_median_process_command_line_entropy_by_user_ea` to minimize false positives based on your environment (False positive analysis section in rule).
*   Create a case management workflow triggered by the "High Command Line Entropy Detected for Privileged Commands" rule to ensure alerts are promptly investigated.
*   Implement the remediation steps outlined in the investigation guide to contain and eradicate any confirmed malicious activity (Response and remediation section).
