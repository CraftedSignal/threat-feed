---
title: Detection of Windows Service Binaries in Suspicious Directories
slug: 2026-09-service-binary-suspicious-folder
description: Adversaries often achieve persistence by registering malicious Windows services with binaries located in writeable or temp directories to evade detection.
date: "2026-09-01T11:06:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - defense-impairment
  - windows-registry
  - detection-engineering
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The rule detects the creation of a service by modifying registry keys under HKLM\System\CurrentControlSet\Services.
    confidence_band: high
rules:
  - title: Detect Service Binary in Suspicious Folder via Registry
    description: Detects the creation or modification of a Windows service where the binary path resides in a suspicious directory, often used for persistence.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect service registration in suspicious paths.
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition in brief
  mitigation_plan:
    - priority: medium_term
      action: Restrict write permissions for non-admin users to Temp, Public, and Perflogs directories.
      owner: IT Operations
      evidence: General system hardening best practices
---

Persistence mechanisms on Windows often involve the registration of new services that execute arbitrary binaries. To avoid detection, attackers frequently place these malicious service binaries in directories that are commonly writeable by users or are used for temporary storage, such as \Users\Public\, \Perflogs\, or \Temp\. This technique allows for the execution of malicious payloads with high privileges once the service is started. Security teams should monitor modifications to the HKLM\System\CurrentControlSet\Services registry hive, specifically focusing on the ImagePath and Start values, to identify when services are configured to execute binaries from non-standard or suspicious file paths.

## Impact

Successful exploitation of this technique allows attackers to gain persistence, execute arbitrary code with SYSTEM privileges, and potentially impair security controls. This is a common TTP observed across various intrusion campaigns targeting Windows endpoints.

## Recommendation

Detection engineering teams should monitor registry modifications to identify unauthorized service creation.
- Deploy the Sigma rule below to detect service registration pointing to suspicious directories.
- Review registry events for modifications to HKLM\System\CurrentControlSet\Services.
- Investigate any service binary path that resides outside of standard system directories like C:\Windows\System32 or C:\Program Files.
