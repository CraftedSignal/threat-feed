---
title: ProblemChild ML Detection of Suspicious Windows Processes
slug: 2024-01-problemchild-suspicious-windows-processes
description: The ProblemChild machine learning model has detected a user with suspicious Windows processes exhibiting unusually high malicious probability scores, potentially indicating defense evasion via masquerading or LOLbins.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
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
  - title: Detect Suspicious Process Execution via LOLBins
    description: Detects the execution of known LOLBins with command line arguments often associated with malicious activities
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Image Masquerading
    description: Detects processes masquerading as legitimate system binaries by renaming or copying themselves
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Elastic ProblemChild integration leverages machine learning to identify suspicious Windows process clusters associated with specific users. This detection focuses on processes flagged as malicious by a supervised ML model, further refined by an unsupervised ML model that identifies unusually high aggregate scores within process clusters. This combination aims to detect activity that may evade traditional signature-based detections, such as the use of Living-off-the-Land Binaries (LOLbins) for masquerading. The models are trained to identify processes exhibiting characteristics indicative of malicious intent, making it possible to expose attackers using legitimate system tools for malicious purposes. The integration requires Windows process events collected by Elastic Defend or Winlogbeat and the Living off the Land (LotL) Attack Detection integration assets to be installed.

## Attack Chain

1. An attacker gains initial access to a Windows system.
2. The attacker attempts to execute malicious commands using LOLbins (e.g., PowerShell, cmd.exe, mshta.exe).
3. These processes are spawned with potentially obfuscated or unusual command-line arguments to evade basic detection.
4. The ProblemChild supervised ML model analyzes process characteristics and assigns a malicious probability score.
5. An unsupervised ML model aggregates the scores of related processes associated with the same user, identifying unusually high clusters.
6. The rule triggers based on the combined supervised and unsupervised ML scores, indicating a high likelihood of malicious activity.
7. The attacker may attempt to use masquerading techniques to further disguise their actions by renaming files or using legitimate process names.
8. The ultimate goal could be data exfiltration, lateral movement, or establishing persistence on the compromised system.

## Impact

A successful attack leveraging LOLbins and masquerading techniques can lead to significant damage, including data breaches, system compromise, and disruption of services. The use of legitimate tools makes detection challenging, potentially allowing attackers to operate undetected for extended periods. While the number of victims and specific sectors are unknown, any organization running Windows systems is potentially vulnerable. The impact of a successful attack depends on the attacker's objectives but can range from minor data theft to complete system takeover.

## Recommendation

*   Ensure the Living off the Land (LotL) Attack Detection integration assets are installed and properly configured as described in the setup instructions of the rule.
*   Deploy the "User Detected with Suspicious Windows Process(es)" ML job (machine_learning_job_id: `problem_child_high_sum_by_user_ea`) and tune the anomaly threshold for your environment.
*   Enable Windows process event collection via Elastic Defend or Winlogbeat (Rule Setup) to provide the necessary data for the ML models.
*   Review and whitelist legitimate administrative tools and software updates that may trigger false positives, as described in the False Positive Analysis section of the rule note.
*   Implement enhanced monitoring and detection rules to identify similar patterns of behavior in the future, focusing on the specific tactics and techniques used in this incident (Rule Note).
