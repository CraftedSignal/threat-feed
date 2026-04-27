---
title: NestJS Uncontrolled Recursion Denial-of-Service Vulnerability (CVE-2026-40879)
slug: 2026-04-nest-recursion-dos
description: NestJS versions before 11.1.19 are susceptible to an uncontrolled recursion vulnerability (CVE-2026-40879) where sending many small JSON messages in a single TCP frame triggers a call stack overflow, resulting in a denial-of-service condition.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - denial-of-service
  - nestjs
  - recursion
  - cve-2026-40879
  - linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40879
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40879
  - https://github.com/nestjs/nest/security/advisories/GHSA-hpwf-8g29-85qm
rules:
  - title: Detect Suspicious NestJS TCP Payload
    description: Detects potentially malicious TCP payloads sent to NestJS applications that may trigger CVE-2026-40879.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - network_connection
      - linux
  - title: Detect RangeError in NestJS Application Logs
    description: Detects RangeError exceptions in NestJS application logs, which may indicate a successful exploit of CVE-2026-40879.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

NestJS, a Node.js framework for server-side applications, is vulnerable to an uncontrolled recursion issue. Prior to version 11.1.19, a malicious actor could exploit CVE-2026-40879 by sending a crafted TCP frame containing numerous small, valid JSON messages to a vulnerable NestJS application. The `handleData()` function recursively processes each message, causing the buffer to shrink with each call. This bypasses the `maxBufferSize` limit and leads to a call stack overflow. A payload as small…
