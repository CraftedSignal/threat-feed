---
title: Detection of Common Ransomware Notes
slug: 2026-07-common-ransomware-notes
description: This brief details the detection of files commonly associated with ransomware notes on endpoints, indicating active data encryption and potential extortion attempts by various threat actors.
date: "2026-07-27T18:14:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - impact
  - endpoint-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The following analytic detects the creation of files with names commonly associated with ransomware notes. If confirmed malicious, this activity could result in significant data loss, operational disruption, and financial impact due to ransom demands.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/common_ransomware_notes.yml
rules:
  - title: Detect Common Ransomware Note Creation
    description: Detects the creation or modification of files with names commonly associated with ransomware notes, indicating potential ransomware activity and data encryption (T1485).
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This threat brief focuses on the detection of ransomware notes, which are critical indicators of active ransomware attacks. Ransomware notes are text files left by threat actors after encrypting an organization's data, typically containing instructions on how to pay the ransom to decrypt files. This detection relies on monitoring file system activity, specifically the creation or modification of files with names commonly used by various ransomware families. Endpoint Detection and Response (EDR) tools or Sysmon logs, providing file system activity data, are crucial for this detection. The immediate presence of a ransomware note signifies that an attacker has successfully breached defenses, executed ransomware, and encrypted data, leading to severe operational disruption, data loss, and significant financial demands. Maintaining an up-to-date list of known ransomware note filenames is essential for effective and timely detection of these impactful attacks.

## Attack Chain

1. Ransomware payload is executed on an endpoint, often through various initial access vectors such as phishing or exploiting vulnerabilities.
2. The ransomware identifies target files and directories for encryption.
3. Ransomware encrypts target files using a cryptographic algorithm.
4. The ransomware creates or modifies a file on the compromised system, typically in multiple directories where files were encrypted, containing the ransom demand and payment instructions.
5. The presence of these specific files (ransomware notes) serves as a direct indicator of successful encryption and active extortion.

## Impact

The successful deployment and execution of ransomware, evidenced by the creation of ransomware notes, leads to immediate and severe consequences. Organizations face significant data loss due to encrypted files, operational disruption as critical systems become inaccessible, and potential financial impact from ransom demands. Beyond the direct financial cost, there can be severe reputational damage, regulatory fines, and long-term recovery efforts. The scope of impact can range from individual systems to entire network infrastructures, depending on the ransomware's propagation capabilities.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune it for your environment to detect ransomware note creation.
* Enable Sysmon process-creation and file-event logging (Event ID 11) on all Windows endpoints to ensure the necessary telemetry for the rule.
* Ensure your EDR solution is configured to log file creation and modification events for activating relevant detections.
* Regularly update the list of known ransomware note filenames in your detection platform to cover emerging threats.
