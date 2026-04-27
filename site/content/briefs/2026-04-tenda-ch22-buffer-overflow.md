---
title: Tenda CH22 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-ch22-buffer-overflow
description: A stack-based buffer overflow vulnerability in Tenda CH22 version 1.0.0.1 allows a remote attacker to execute arbitrary code by manipulating the 'GO' argument in the formWrlExtraSet function via the /goform/WrlExtraSet endpoint.
date: "2026-04-06T12:00:00Z"
severities:
  - critical
tags:
  - CVE-2026-5605
  - buffer-overflow
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-5605
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5605
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_54/README.md
  - https://vuldb.com/vuln/355397
rules:
  - title: Detect Tenda CH22 Buffer Overflow Attempt via Long GO Parameter
    description: Detects potential exploitation attempts of the Tenda CH22 buffer overflow vulnerability (CVE-2026-5605) by identifying abnormally long 'GO' parameters in POST requests to the /goform/WrlExtraSet endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Tenda CH22 formWrlExtraSet Endpoint
    description: Detects access to the /goform/WrlExtraSet endpoint on Tenda CH22 routers, which could indicate reconnaissance or exploitation attempts related to CVE-2026-5605.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-5605, affects Tenda CH22 router version 1.0.0.1. This flaw resides in the `formWrlExtraSet` function within the `/goform/WrlExtraSet` file. A remote, unauthenticated attacker can exploit a stack-based buffer overflow by sending a crafted HTTP request with a malicious value for the `GO` argument. Publicly available exploits exist, increasing the risk of widespread exploitation. Successful exploitation allows the attacker to potentially execute…
