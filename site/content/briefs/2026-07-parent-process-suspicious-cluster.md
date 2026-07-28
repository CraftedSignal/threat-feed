---
title: Parent Process Detected with Suspicious Windows Process(es)
slug: 2026-07-parent-process-suspicious-cluster
description: Elastic's machine learning models detect clusters of suspicious Windows processes that share a common parent process and exhibit unusually high malicious probability scores, aiming to uncover stealthy attacks, including those leveraging Living off the Land Binaries (LOLBins) and masquerading techniques, which might otherwise evade traditional detection methods.
date: "2026-07-28T18:23:45Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - endpoint
  - windows
  - machine-learning
  - defense-evasion
  - lolbins
  - masquerading
  - investigation-guide
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The detection rule employs machine learning to identify clusters of processes with high malicious probability, focusing on those sharing a common parent process. This approach helps uncover stealthy attacks that traditional methods might miss, enhancing defense against tactics like masquerading.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries exploit this by using legitimate processes to launch malicious ones, often leveraging Living off the Land Binaries (LOLBins) to evade detection. ... Such a cluster often contains suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/problemchild/defense_evasion_ml_suspicious_windows_process_cluster_from_parent_process.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/problemchild
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
---

Elastic's machine learning job combination, 'problem_child_high_sum_by_parent_ea', is designed to identify suspicious clusters of Windows processes originating from a common parent process. This detection mechanism, active since at least October 2023 and continuously updated, leverages supervised and unsupervised ML models to assign high malicious probability scores to processes, even those employing Living off the Land Binaries (LOLBins) or masquerading techniques to evade conventional detection rules. The primary objective is to enhance defense against stealthy attacks by flagging patterns that indicate malicious activity, focusing on defense evasion tactics within Windows environments. This approach is critical for surfacing threats that might otherwise go unnoticed by signature-based or simple rule-based detections.

## Attack Chain

This brief describes a detection capability for attacker activity, rather than an observed attack chain. The underlying attack chain that this rule would detect generally involves an initial compromise, followed by execution of malicious code, often using legitimate system processes or LOLBins to masquerade as benign activity. The attacker aims to establish persistence, escalate privileges, and achieve their objectives while blending in with normal system operations.

## Impact

This threat brief describes a detection rule designed to identify malicious activity, rather than detailing the direct impact of an attack. The successful deployment and tuning of this detection rule would result in improved visibility into sophisticated and stealthy attacks that utilize LOLBins and process masquerading. Without such detection, organizations would remain vulnerable to these advanced techniques, potentially leading to unauthorized data access, system compromise, or network lateral movement, which are challenging to detect through traditional security measures.

## Recommendation

* Enable Windows process event logging and ensure it is collected by Elastic Defend or Winlogbeat to provide the necessary data for the ML job.
* Install the Living off the Land (LotL) Attack Detection integration assets in Fleet and complete the setup, including adding preconfigured anomaly detection jobs.
* Investigate the parent process name associated with any detected suspicious process cluster to identify potential masquerading attempts.
* Examine the command line arguments and execution context of suspicious processes flagged by the ML rule for LOLBins or unusual patterns.
* Cross-reference detected processes with threat intelligence sources to identify known Indicators of Compromise (IOCs) or related threat actor activity.
* Review the false positives section for common legitimate activities that might trigger the rule, such as administrative tools, software updates, or automated scripts, and consider creating exceptions for verified safe tools or activities.
* Isolate affected systems, terminate suspicious processes, and conduct thorough remediation if a confirmed threat is identified to prevent further spread.
