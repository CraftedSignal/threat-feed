---
title: Suspicious Windows Process Cluster Detection via Machine Learning
slug: 2024-01-suspicious-windows-process
description: A machine learning job combination has identified a host with one or more suspicious Windows processes that exhibit unusually high malicious probability scores, potentially indicating masquerading and defense evasion tactics.
date: "2024-01-03T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - masquerading
  - LOLbins
  - windows
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
  - title: Detect Potential LOLBin Execution via Image Path
    description: Detects potential LOLBin execution by monitoring process creations from non-standard system directories. This rule looks for processes spawned from unusual locations, which could indicate an attempt to masquerade malicious activity.
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
  - title: Detect Suspicious Process Spawning LOLBins
    description: Detects potentially suspicious process spawning LOLBins, such as cmd.exe, powershell.exe or mshta.exe, from unusual parent processes. It helps identify potentially malicious processes trying to leverage LOLBins for nefarious activities.
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

This detection identifies suspicious Windows processes exhibiting high malicious probability scores. The rule leverages machine learning to detect clusters of processes that may be indicative of defense evasion tactics, such as masquerading or the use of LOLbins (Living Off The Land Binaries). Specifically, a supervised ML model (ProblemChild) predicts whether a process is malicious, and an unsupervised ML model assesses the aggregate score of process clusters on a single host. The rule focuses on identifying unusual process clusters on a single host, indicating potential masquerading tactics for defense evasion. The rule requires the Living off the Land (LotL) Attack Detection integration assets to be installed, as well as Windows process events collected by integrations such as Elastic Defend or Winlogbeat. It was last updated on 2026/04/01 and requires Elastic Stack version 9.4.0 or later.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the Windows host through various methods, such as exploiting vulnerabilities or using compromised credentials (not detailed in source).
2.  Execution: The attacker executes a LOLBin (e.g., PowerShell, cmd.exe, mshta.exe) on the compromised host.
3.  Masquerading: The attacker attempts to masquerade the malicious activity by naming or placing the LOLBin within a legitimate system folder.
4.  Defense Evasion: The attacker utilizes the LOLBin with specific command-line arguments designed to evade detection by traditional signature-based security solutions.
5.  Privilege Escalation (Optional): The attacker may attempt to escalate privileges using further LOLBINS or other techniques.
6.  Lateral Movement (Optional): The attacker may use the compromised host to move laterally to other systems within the network.
7.  Command and Control (Optional): The attacker may establish command and control (C2) communication with an external server to receive further instructions.
8.  Impact: The attacker achieves their objective, such as data exfiltration, ransomware deployment, or system disruption.

## Impact

A successful attack can lead to various negative impacts, including data breaches, financial loss, and reputational damage. The rule is assigned a low severity, due to it likely being a supplemental detection to other rules. Lateral movement and exfiltration can also be accomplished. There is no information available on the number of victims and specific sectors targeted.

## Recommendation

*   Ensure the Living off the Land (LotL) Attack Detection integration is installed and configured correctly, along with either Elastic Defend or Winlogbeat, to collect Windows process events as outlined in the [setup instructions](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html).
*   Review the host name associated with the suspicious process cluster to determine if it is a critical asset or has a history of similar alerts as suggested in the investigation guide.
*   Examine the specific processes flagged by the ProblemChild supervised ML model to identify any known LOLbins or unusual command-line arguments that may indicate masquerading, per the investigation guide.
*   Implement application whitelisting to prevent unauthorized or suspicious processes from executing in the future, as advised in the remediation steps.
*   Tune the anomaly threshold of the machine learning job (`problem_child_high_sum_by_host_ea`) to reduce false positives based on your environment's specific characteristics and activity patterns.
