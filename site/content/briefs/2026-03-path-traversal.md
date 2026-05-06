---
title: CVE-2026-2328 Unauthenticated Path Traversal Vulnerability
slug: 2026-03-path-traversal
description: CVE-2026-2328 describes a vulnerability where an unauthenticated remote attacker can exploit insufficient input validation to access backend components beyond their intended scope via path traversal, leading to the exposure of sensitive information.
date: "2026-03-30T08:16:17Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - vulnerability
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2328
  - https://certvde.com/de/advisories/VDE-2026-010
rules:
  - title: Detect Path Traversal Attempts in HTTP Requests
    description: Detects suspicious HTTP requests containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Files via Webserver
    description: Detects web server access to sensitive files like /etc/passwd or web.config
    platform: sigma
    severity: critical
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-2328 is a critical vulnerability that allows an unauthenticated remote attacker to perform path traversal attacks due to insufficient input validation. This flaw enables unauthorized access to backend components, potentially exposing sensitive information. The vulnerability was published on March 30, 2026, and assigned a CVSS v3.1 score of 7.5. The vulnerability stems from inadequate input sanitization, permitting attackers to manipulate file paths and access restricted areas of the…
