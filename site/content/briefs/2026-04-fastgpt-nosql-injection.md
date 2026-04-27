---
title: FastGPT NoSQL Injection Vulnerability (CVE-2026-40351)
slug: 2026-04-fastgpt-nosql-injection
description: FastGPT versions before 4.14.9.5 are vulnerable to NoSQL injection, allowing unauthenticated attackers to bypass authentication and gain administrative access.
date: "2026-04-18T12:00:00Z"
severities:
  - critical
tags:
  - NoSQL injection
  - authentication bypass
  - CVE-2026-40351
  - FastGPT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40351
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40351
  - https://github.com/labring/FastGPT/commit/bd966d479fbe414d02679cf79f9eaaab3d100a2d
  - https://github.com/labring/FastGPT/releases/tag/v4.14.9.5
  - https://github.com/labring/FastGPT/security/advisories/GHSA-x8mx-2mr7-h9xg
ioc_counts:
  url: 3
rules:
  - title: Detect FastGPT NoSQL Injection Attempt
    description: Detects attempts to exploit the NoSQL injection vulnerability in FastGPT by searching for MongoDB query operators in POST requests to the login endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect FastGPT Version Pre 4.14.9.5 in User Agent
    description: Detects connections to FastGPT with a User-Agent string indicating a version prior to the patched version.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FastGPT is an AI Agent building platform. Versions prior to 4.14.9.5 are susceptible to a critical NoSQL injection vulnerability (CVE-2026-40351) affecting the password-based login endpoint. The vulnerability stems from the use of TypeScript type assertion without runtime validation, enabling unauthenticated attackers to inject MongoDB query operators within the password field. This bypasses the intended password check, granting the attacker the ability to authenticate as any user, including…
