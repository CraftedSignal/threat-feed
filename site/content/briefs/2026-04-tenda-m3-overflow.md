---
title: Tenda M3 Router Buffer Overflow Vulnerability
slug: 2026-04-tenda-m3-overflow
description: A buffer overflow vulnerability exists in Tenda M3 1.0.0.10 via manipulation of the policyType argument in the setAdvPolicyData function, allowing remote attackers to execute arbitrary code.
date: "2026-04-05T13:17:14Z"
severities:
  - critical
tags:
  - cve-2026-5567
  - buffer-overflow
  - tenda
  - router
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-5567
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5567
  - https://github.com/Moxxkidd/CVE/issues/2
  - https://vuldb.com/vuln/355337
rules:
  - title: Detect Suspicious PolicyType Argument Length
    description: Detects HTTP POST requests to /goform/setAdvPolicyData with an unusually long policyType argument, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Tenda Configuration Endpoint After Exploitation
    description: Detects access to sensitive Tenda configuration endpoints after potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability has been identified in Tenda M3 router version 1.0.0.10. The vulnerability resides in the `setAdvPolicyData` function within the `/goform/setAdvPolicyData` file, a part of the Destination Handler component. By manipulating the `policyType` argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability poses a…
