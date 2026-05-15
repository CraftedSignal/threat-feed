---
title: Host Detected with Suspicious Windows Process(es)
slug: 2026-05-suspicious-windows-processes
description: A machine learning job combination has identified a host with one or more suspicious Windows processes that exhibit unusually high malicious probability scores, indicating potential masquerading tactics for defense evasion.
date: "2026-05-15T18:08:09Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - 'Use Case: Living off the Land Attack Detection'
  - 'Rule Type: ML'
  - 'Rule Type: Machine Learning'
  - 'Tactic: Defense Evasion'
  - 'Resources: Investigation Guide'
  - defense-evasion
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
  - Winlogbeat
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
  - title: Detect Windows Processes Identified as Suspicious by ProblemChild Model
    description: Detects Windows processes flagged as suspicious based on ProblemChild supervised ML model.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
  - title: Detect LOLBins Execution
    description: Detects execution of commonly used LOLBins (Living Off The Land Binaries).
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies hosts with suspicious Windows processes exhibiting unusually high malicious probability scores, leveraging machine learning to detect potential masquerading tactics for defense evasion. The rule utilizes a combination of supervised and unsupervised ML models to flag unusual process clusters on a single host, possibly involving LOLbins. This approach aims to identify activity that may be resistant to detection using conventional search rules. The rule relies on the 'problem_child_high_sum_by_host_ea' machine learning job and requires a minimum Elastic Stack version of 9.4.0. The rule uses data ingested by the Elastic Defend or Winlogbeat integrations.

## Attack Chain

1.  Initial access is achieved through methods not specified in this source.
2.  The attacker executes a legitimate Windows binary (LOLBin) such as cmd.exe, powershell.exe or certutil.exe.
3.  The LOLBin is used to execute a malicious command or script.
4.  The ProblemChild supervised ML model predicts that the process is malicious based on its behavior.
5.  An unsupervised ML model analyzes the aggregate score of the process cluster, identifying it as unusually high.
6.  The detection rule triggers, flagging the host as having suspicious processes.
7.  The analyst reviews the alert and investigates the flagged processes.
8.  The attacker continues their actions on the compromised host, potentially leading to data exfiltration or other malicious activities.

## Impact

A successful attack using LOLBins and masquerading techniques can allow an attacker to evade traditional detection methods and gain unauthorized access to sensitive systems and data. This can lead to data breaches, financial loss, and reputational damage. While the number of victims is unknown, the sectors targeted include any organization utilizing Windows systems.

## Recommendation

*   Ensure the Living off the Land (LotL) Attack Detection integration assets are installed, along with Windows process events collected by Elastic Defend or Winlogbeat, as required by the [setup instructions](#setup).
*   Review the host name associated with the suspicious process cluster as described in the [investigation guide](#triage-and-analysis).
*   Examine the specific processes flagged by the ProblemChild supervised ML model to identify any known LOLbins as described in the [investigation guide](#triage-and-analysis).
*   Implement application whitelisting to prevent unauthorized or suspicious processes from executing, as mentioned in the [response and remediation steps](#response-and-remediation).
