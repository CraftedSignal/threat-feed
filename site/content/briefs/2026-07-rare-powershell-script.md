---
title: Detection of Rare PowerShell Scripts on Windows Systems
slug: 2026-07-rare-powershell-script
description: Elastic's machine learning job detects rare PowerShell script executions on Windows hosts, identified by their script block hash, indicating potential malware activity or persistence mechanisms that deviate from an established baseline.
date: "2026-07-27T15:31:41Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - windows
  - machine-learning
  - powershell
  - execution
  - threat-detection
vendors:
  - Elastic
products:
  - Kibana 9.4.0+
  - Elastic Agent System Windows Integration
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A machine learning job detected a rare PowerShell script, identified by its script block hash, that may indicate execution of malware, or persistence mechanisms.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
---

Elastic has developed a machine learning rule to identify the execution of rare PowerShell scripts on Windows systems, leveraging script block hashes to detect deviations from established environmental baselines. This detection method focuses on scripts that have rarely or never been observed within a specific Windows host's historical activity, differentiating it from entropy-based anomaly detection. The objective is to uncover potentially malicious activity such as malware execution, the establishment of persistence mechanisms, or other suspicious behaviors that leverage PowerShell. This rule is integrated into the Elastic security platform, requiring specific ML jobs and data from the Windows integration to be active in Kibana version 9.4.0 or higher. While the rule identifies unusual behavior, false positives may occur with newly installed legitimate programs or infrequently run legitimate scripts.

## Attack Chain

This brief describes a detection methodology rather than a specific attack chain. The Elastic machine learning rule is designed to identify the *execution* phase of an attack, specifically focusing on the rarity of PowerShell script blocks. When an attacker executes a novel or infrequently used PowerShell script, whether for initial payload delivery, command and control, persistence, or data exfiltration, this ML rule aims to flag the anomalous execution. It does not cover the initial access vector but rather the post-exploitation activity where PowerShell is often heavily utilized. The detection focuses on the inherent unusualness of the script itself within the context of the monitored environment.

## Impact

The successful execution of rare PowerShell scripts, if malicious, can lead to severe consequences, including system compromise, data theft, and the deployment of ransomware. Such scripts are frequently used by threat actors for various post-exploitation activities like privilege escalation, lateral movement, establishing persistence, or directly executing payloads. If this activity goes undetected, attackers can maintain a foothold within the network, escalate privileges, exfiltrate sensitive data, disrupt operations through ransomware, or deploy destructive malware. Early detection of such anomalous PowerShell usage is critical for containing potential breaches and mitigating their impact before significant damage occurs.

## Recommendation

* Deploy the `v3_windows_rare_script_ea` machine learning job to your Elastic environment to enable this detection rule.
* Ensure the Elastic Agent System `windows` integration is properly configured and collecting PowerShell script block logs on all Windows hosts.
* Upon detection, investigate the PowerShell script block hash by retrieving the full script content and examining it for malicious indicators using tools like VirusTotal, Hybrid-Analysis, or Any.run.
* Analyze the process execution chain (parent process tree) of the PowerShell process flagged by the rule to determine its origin and legitimacy.
* Review the `user.name` field associated with the alert to determine if the activity is part of an expected workflow for that user.
