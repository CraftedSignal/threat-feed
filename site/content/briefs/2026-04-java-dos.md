---
title: Oracle Java SE, GraalVM Networking Component Denial-of-Service Vulnerability (CVE-2026-34282)
slug: 2026-04-java-dos
description: CVE-2026-34282 is a remotely exploitable vulnerability in the Networking component of Oracle Java SE and GraalVM that allows an unauthenticated attacker to cause a complete denial of service.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - CVE-2026-34282
  - java
  - graalvm
  - dos
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-34282
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34282
rules:
  - title: Detect Suspicious Java Network Activity
    description: Detects unusual network activity by Java processes that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Java Process Crashing
    description: Detects Java processes that crash, potentially indicating a denial-of-service condition related to CVE-2026-34282.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-34282 is a critical vulnerability affecting the Networking component of Oracle Java SE, Oracle GraalVM for JDK, and Oracle GraalVM Enterprise Edition. The vulnerability, present in versions 8u481-perf, 11.0.30, 17.0.18, 21.0.10, 25.0.2, and 26 of Oracle Java SE, GraalVM for JDK versions 17.0.18 and 21.0.10, and GraalVM Enterprise Edition 21.3.17, allows an unauthenticated attacker with network access to trigger a complete denial-of-service (DoS) condition. This is achieved by sending…
