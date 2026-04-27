---
title: Openfind MailGates/MailAudit Stack-based Buffer Overflow (CVE-2026-6350)
slug: 2026-04-openfind-mailgates-bo
description: Openfind MailGates/MailAudit is vulnerable to a stack-based buffer overflow (CVE-2026-6350) allowing unauthenticated remote attackers to execute arbitrary code by controlling the program's execution flow.
date: "2026-04-16T03:16:30Z"
severities:
  - critical
tags:
  - cve-2026-6350
  - buffer-overflow
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6350
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6350
  - https://www.twcert.org.tw/en/cp-139-10843-9ff91-2.html
  - https://www.twcert.org.tw/tw/cp-132-10844-1405d-1.html
rules:
  - title: Detect CVE-2026-6350 Exploitation Attempts via URI Length
    description: Detects potential exploitation attempts of CVE-2026-6350 by monitoring for abnormally long URIs in web server logs, which may indicate a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect CVE-2026-6350 Exploitation Attempts via HTTP Method
    description: Detects potential exploitation attempts of CVE-2026-6350 by monitoring for POST requests to specific MailGates URIs, as buffer overflows are often triggered via POST requests.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Openfind MailGates and MailAudit are susceptible to a critical stack-based buffer overflow vulnerability, identified as CVE-2026-6350. This flaw allows unauthenticated remote attackers to gain control over the program's execution flow and execute arbitrary code on the affected system. The vulnerability stems from insufficient input validation, leading to a buffer overflow when processing specifically crafted requests. Given the nature of MailGates/MailAudit as email security solutions…
