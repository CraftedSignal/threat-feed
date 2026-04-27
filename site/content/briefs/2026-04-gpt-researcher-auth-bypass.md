---
title: GPT Researcher Authentication Bypass Vulnerability (CVE-2026-5632)
slug: 2026-04-gpt-researcher-auth-bypass
description: CVE-2026-5632 is an authentication bypass vulnerability in assafelovic gpt-researcher up to version 3.4.3, affecting the HTTP REST API Endpoint and allowing remote attackers to perform actions without proper authorization.
date: "2026-04-06T07:16:02Z"
severities:
  - high
tags:
  - CVE-2026-5632
  - authentication-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5632
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5632
  - https://github.com/assafelovic/gpt-researcher/
  - https://github.com/assafelovic/gpt-researcher/issues/1695
  - https://vuldb.com/vuln/355420
rules:
  - title: Detect GPT Researcher Authentication Bypass Attempt
    description: Detects potential attempts to exploit the CVE-2026-5632 authentication bypass vulnerability in gpt-researcher.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: GPT Researcher API Access Without Authentication Cookie
    description: Detects access to GPT Researcher API endpoints without a valid authentication cookie, indicating potential unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability, CVE-2026-5632, has been identified in assafelovic's gpt-researcher up to version 3.4.3. The vulnerability resides within the HTTP REST API Endpoint component. A remote attacker can exploit this flaw by manipulating requests, effectively bypassing authentication mechanisms. This issue allows unauthorized access to functionalities that should be protected. A proof-of-concept exploit is publicly available, increasing the risk of exploitation. Despite…
