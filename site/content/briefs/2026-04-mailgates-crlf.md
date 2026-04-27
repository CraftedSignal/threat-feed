---
title: Openfind MailGates/MailAudit CRLF Injection Vulnerability
slug: 2026-04-mailgates-crlf
description: Openfind MailGates/MailAudit is vulnerable to CRLF injection (CVE-2026-6351), enabling unauthenticated remote attackers to read system files by injecting malicious CRLF sequences.
date: "2026-04-16T03:17:58Z"
severities:
  - high
tags:
  - crlf-injection
  - vulnerability
  - mailgates
  - mailaudit
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6351
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6351
  - https://www.twcert.org.tw/en/cp-139-10843-9ff91-2.html
  - https://www.twcert.org.tw/tw/cp-132-10844-1405d-1.html
rules:
  - title: Detect Suspicious CRLF Injection Attempts
    description: Detects HTTP requests containing CRLF sequences, indicative of CRLF injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Headers via CRLF Injection
    description: Detects suspicious headers such as Content-Type when found in the URL, which is indicative of CRLF injection.
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

Openfind MailGates and MailAudit are susceptible to a CRLF injection vulnerability identified as CVE-2026-6351. This flaw allows unauthenticated remote attackers to inject carriage return and line feed characters into HTTP headers. By manipulating these headers, attackers can potentially read system files due to the application's failure to properly neutralize CRLF sequences. This can lead to information disclosure and potentially further compromise of the affected system. The vulnerability was…
