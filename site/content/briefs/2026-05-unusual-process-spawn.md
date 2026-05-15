---
title: Unusual Process Spawned by a Parent Process via Machine Learning
slug: 2026-05-unusual-process-spawn
description: This rule detects unusual process spawned by a parent process, potentially indicating malicious activity involving LOLbins by leveraging machine learning to identify anomalous process creation patterns that evade conventional search rules.
date: "2026-05-15T18:07:40Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - lolbin
  - machine-learning
  - windows
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
rules:
  - title: Detect LOLBin Use via Process Creation Event
    description: Detects use of LOLBins like certutil, powershell, or cmd.exe with unusual parent processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect Masquerading via Renamed Binary
    description: Detects renamed system binaries being executed, indicating masquerading (T1036).
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious Windows processes using machine learning. The processes are classified as potentially malicious in two ways: prediction by the ProblemChild supervised ML model and identification as an unusual child process name for its parent process by an unsupervised ML model. This combination indicates potentially malicious activity, possibly involving Living Off The Land Binaries (LOLbins), designed to evade traditional detection methods. The rule requires the Living off the Land (LotL) Attack Detection integration assets to be installed, as well as Windows process events collected by integrations such as Elastic Defend or Winlogbeat. The rule is designed to identify anomalous process spawns from unusual parent-child relationships in Windows environments.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means (e.g., phishing, exploiting a vulnerability).
2. The attacker uses a legitimate system binary (LOLbin) like `powershell.exe` or `cmd.exe` to execute malicious commands.
3. The attacker attempts to masquerade their activity by spawning the LOLbin process from a legitimate parent process.
4. The executed command performs reconnaissance activities such as gathering system information or network configuration.
5. The attacker leverages the LOLbin to download and execute a malicious payload from a remote server.
6. The malicious payload establishes persistence on the system, ensuring continued access.
7. The attacker uses the compromised system to move laterally within the network, compromising additional systems.

## Impact

Successful exploitation can lead to unauthorized access, data theft, or system compromise. This rule aims to detect early stages of a potential attack, which minimizes the impact. Failure to detect such activity can result in a full system compromise, potential data exfiltration, and further propagation of malicious activity within the network. Due to the broad nature of LOLBin attacks the impact is difficult to quantify, but detection of anomalous activity early in the attack chain is critical.

## Recommendation

*   Install the Living off the Land (LotL) Attack Detection integration assets to enable the machine learning jobs (references: [https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html), [https://docs.elastic.co/en/integrations/problemchild](https://docs.elastic.co/en/integrations/problemchild), [https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration)).
*   Ensure Windows process events are collected by Elastic Defend or Winlogbeat as required by the rule setup.
*   Tune the `Unusual Process Spawned by a Parent Process` rule to reduce false positives by creating exceptions for known and trusted parent-child process relationships as described in the false positive analysis section.
