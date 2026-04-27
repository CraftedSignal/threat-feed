---
title: TIBCO ActiveMatrix Vulnerability Allows Information Disclosure and Data Manipulation
slug: 2026-03-tibco-vuln
description: A remote, authenticated attacker can exploit a vulnerability in TIBCO ActiveMatrix and TIBCO Administrator to disclose information and manipulate data, potentially leading to unauthorized access and control.
date: "2026-03-25T11:31:01Z"
severities:
  - high
tags:
  - tibco
  - vulnerability
  - information-disclosure
  - data-manipulation
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Denial
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0842
rules:
  - title: Detect Suspicious TIBCO ActiveMatrix API Requests
    description: Detects suspicious API requests to TIBCO ActiveMatrix that may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - impact
    data_sources:
      - webserver
      - linux
  - title: Detect TIBCO Administrator Authentication Failures Followed by Success
    description: Detects a pattern of authentication failures followed by a successful login, which could indicate brute-force attempts to gain access to TIBCO Administrator.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists within TIBCO ActiveMatrix and TIBCO Administrator that could allow a remote, authenticated attacker to compromise the system. The specific version numbers affected are not specified. This vulnerability, discovered in March 2026, allows an attacker to both disclose sensitive information and manipulate data within the affected systems. While the exact delivery mechanism is unclear from the source, the requirement for authentication suggests potential exploitation via…
