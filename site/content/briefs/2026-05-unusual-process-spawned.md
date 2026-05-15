---
title: Unusual Process Spawned by a User Detected via Machine Learning
slug: 2026-05-unusual-process-spawned
description: A machine learning job has detected a suspicious Windows process, predicted to be malicious by the ProblemChild supervised ML model and found to be suspicious given its user context by an unsupervised ML model, indicating potential defense evasion activity involving LOLbins.
date: "2026-05-15T18:07:56Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - machine-learning
  - windows
  - lolbin
vendors:
  - Elastic
products:
  - Elastic Defend
  - Winlogbeat
affected_os:
  - Windows
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
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Detect LOLBin Execution with Unusual CommandLine Arguments
    description: Detects execution of known LOLBins (Living Off The Land Binaries) with command-line arguments indicative of malicious activity, possibly used for defense evasion.
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
  - title: Detect Suspicious Cmd Execution with Hidden Window
    description: Detects cmd.exe execution with /c parameter and start /min which could indicate attempts to hide command execution.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule leverages machine learning to identify unusual process execution patterns on Windows systems. It uses the "problem_child_rare_process_by_user_ea" machine learning job to detect processes that are both predicted to be malicious by a supervised model (ProblemChild) and considered unusual based on the user context by an unsupervised model. This approach aims to identify potentially malicious activity, including the use of LOLbins (Living Off The Land binaries), that might evade traditional signature-based detections. The rule is designed to work with data collected by Elastic Defend or Winlogbeat and requires the Living off the Land (LotL) Attack Detection integration to be installed and configured. The integration focuses on identifying defense evasion tactics employed by adversaries.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Windows system through various means (e.g., phishing, exploiting a vulnerability).
2.  Privilege Escalation (Optional): The attacker may attempt to escalate privileges to gain higher access levels on the system.
3.  Defense Evasion: The attacker leverages LOLbins (e.g., `certutil.exe`, `powershell.exe`) to execute malicious commands or download payloads, blending in with legitimate system activity.
4.  Process Execution: The attacker spawns a process using a LOLbin within an unusual user context, making it harder to detect with conventional rules.
5.  Command and Control (Optional): The spawned process establishes a connection to a command-and-control server for further instructions or data exfiltration.
6.  Lateral Movement (Optional): The attacker moves laterally to other systems on the network, using the compromised system as a pivot point.
7.  Data Exfiltration (Optional): The attacker exfiltrates sensitive data from the compromised system or network.
8.  Persistence (Optional): The attacker establishes persistence to maintain access to the system even after a reboot.

## Impact

A successful attack using LOLbins can lead to a variety of negative outcomes, including data theft, system compromise, and disruption of services. While this specific rule has low severity and risk score of 21, the underlying techniques can be part of a larger, more damaging attack. The focus on unusual process execution in user contexts is valuable for catching advanced persistent threats (APTs) or insider threats that have already bypassed initial security layers.

## Recommendation

*   Ensure the Living off the Land (LotL) Attack Detection integration is installed and configured correctly, including the "problem_child_rare_process_by_user_ea" machine learning job as outlined in the [setup instructions](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html).
*   Enable Windows process events collection using Elastic Defend or Winlogbeat, as specified in the [setup section](https://www.elastic.co/guide/en/security/current/install-endpoint.html).
*   Deploy the Sigma rule below to detect unusual process execution involving LOLbins based on command-line arguments, focusing on processes spawned by users in unexpected contexts.
*   Review the triage and analysis steps in the rule's [note section](https://docs.elastic.co/en/integrations/problemchild) to effectively investigate alerts and minimize false positives.
