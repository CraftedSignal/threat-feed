---
title: Detection of Unusual Windows Services via Machine Learning
slug: 2026-07-unusual-windows-service
description: This threat involves the detection of unusual Windows services, which can indicate unauthorized service execution, malware, or persistence mechanisms, with a machine learning job identifying atypical services by comparing them against known legitimate patterns to aid in early threat detection and response.
date: "2026-07-28T18:46:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - machine-learning-detection
  - persistence
  - execution
  - windows
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries exploit this by creating or modifying services to maintain persistence or execute unauthorized actions. The 'Unusual Windows Service' detection rule leverages machine learning to identify atypical services.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
    evidence: Adversaries exploit this by creating or modifying services to maintain persistence or execute unauthorized actions. The 'Unusual Windows Service' detection rule leverages machine learning to identify atypical services.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/persistence_ml_windows_anomalous_service.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
---

Elastic has released a machine learning detection rule designed to identify unusual Windows services running on endpoints. This rule targets the sophisticated persistence and execution mechanisms employed by adversaries who establish unauthorized services to maintain access or execute malicious payloads. The rule leverages an anomaly detection job (`v3_windows_anomalous_service_ea`) to flag services that deviate from established baselines in corporate Windows environments, where service configurations are typically stable. This detection is crucial for identifying stealthy malware, backdoors, or other persistence mechanisms that operate by masquerading as or creating new services. While this brief does not detail a specific adversary campaign, it focuses on the detection capability for a common attacker technique, emphasizing the importance of monitoring service activity for early threat detection.

## Impact

If unusual Windows services are not detected, adversaries can establish persistent access to systems, execute arbitrary code with elevated privileges, and bypass traditional security controls. This can lead to unauthorized data access, intellectual property theft, system compromise, and further lateral movement within an organization's network. The presence of undetected malicious services can also facilitate the deployment of ransomware, wipers, or other destructive malware, causing significant operational disruption and financial loss. Early detection through anomaly-based methods like this machine learning rule helps to mitigate these severe consequences by enabling rapid incident response and remediation.

## Recommendation

* Enable the `v3_windows_anomalous_service_ea` machine learning job within Elastic Security as described in the setup section to leverage anomaly detection for unusual Windows services.
* Ensure Elastic Defend is configured for endpoint integration on all Windows hosts, sending comprehensive endpoint data to Elastic Security to feed the machine learning model.
* Configure the Windows integration within Elastic Agent to collect Windows Security Event Logs from all Windows systems, providing critical data for the ML detection.
* Review the details of any detected unusual Windows service, including the service name, path, and associated executables, to determine legitimacy.
* Investigate the user account running the service and cross-reference the service with known threat intelligence databases for indicators of compromise.
