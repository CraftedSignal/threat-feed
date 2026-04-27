---
title: Plunk Email Platform CRLF Header Injection Vulnerability
slug: 2024-01-30-plunk-crlf
description: A CRLF header injection vulnerability in Plunk versions prior to 0.8.0 allows authenticated API users to inject arbitrary email headers, enabling silent email forwarding, reply redirection, or sender spoofing.
date: "2026-04-06T17:17:11Z"
severities:
  - high
tags:
  - crlf
  - header-injection
  - plunk
  - cve-2026-34975
  - cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1587
    technique_name: Develop Capabilities
cves:
  - id: CVE-2026-34975
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34975
rules:
  - title: Detect Suspicious CRLF Characters in URI Query
    description: Detects suspicious carriage return and line feed characters in URI queries, potentially indicating CRLF injection attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1587.002
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious CRLF Characters in HTTP Request Body
    description: Detects suspicious carriage return and line feed characters in HTTP request body, potentially indicating CRLF injection attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1587.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Plunk, an open-source email platform built on top of AWS SES, is vulnerable to CRLF header injection. Prior to version 0.8.0, the application failed to properly sanitize user-supplied values for fields like `from.name`, `subject`, custom header keys/values, and attachment filenames. This vulnerability, identified as CVE-2026-34975, allows an authenticated API user to inject arbitrary email headers by including carriage return (`\r`) and line feed (`\n`) characters in these fields. Successful…
