---
title: IBM Verify and Security Verify Access Authentication Bypass Vulnerability
slug: 2026-04-ibm-verify-auth-bypass
description: CVE-2026-4101 describes an authentication bypass vulnerability in IBM Verify Identity Access Container and IBM Security Verify Access Container versions 11.0 through 11.0.2 and 10.0 through 10.0.9.1, respectively, that could allow unauthorized access under specific load conditions.
date: "2026-04-01T21:17:02Z"
severities:
  - high
tags:
  - authentication-bypass
  - cve-2026-4101
  - ibm-verify
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Appliances
cves:
  - id: CVE-2026-4101
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4101
  - https://www.ibm.com/support/pages/node/7268253
rules:
  - title: Detect HTTP 500 Errors Potentially Related to CVE-2026-4101
    description: Detects a high number of HTTP 500 errors originating from the IBM Verify or Security Verify Access container, which may indicate an attempt to trigger the authentication bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed Login Attempts from Single IP
    description: Detects multiple failed login attempts within a short timeframe from a single IP address, which could be an attempt to trigger the vulnerability under high load.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
rules_count: 2
---

IBM Verify Identity Access Container and IBM Security Verify Access Container are vulnerable to an authentication bypass vulnerability identified as CVE-2026-4101. The affected versions include IBM Verify Identity Access Container 11.0 through 11.0.2 and IBM Security Verify Access Container 10.0 through 10.0.9.1, as well as IBM Verify Identity Access 11.0 through 11.0.2 and IBM Security Verify Access 10.0 through 10.0.9.1. This vulnerability can be exploited under certain load conditions…
