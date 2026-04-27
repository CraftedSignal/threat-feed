---
title: F5 BIG-IP APM CVE-2025-53521 Reclassified as Actively Exploited Unauthenticated RCE
slug: 2026-04-f5-big-ip-rce
description: F5 has reclassified CVE-2025-53521, a vulnerability in BIG-IP APM, as a critical unauthenticated remote code execution vulnerability and reports it is being actively exploited in the wild.
date: "2026-04-01T12:00:00Z"
severities:
  - critical
exploited: true
tags:
  - f5
  - big-ip
  - apm
  - cve-2025-53521
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2025-53521
    cvss: 9.8
    epss: 0.07452
references:
  - https://arcticwolf.com/resources/blog/cve-2025-53521/
rules:
  - title: Detect CVE-2025-53521 Exploitation Attempt via HTTP Request
    description: Detects potential exploitation attempts of CVE-2025-53521 by monitoring for suspicious HTTP requests to BIG-IP APM.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect CVE-2025-53521 Exploitation Attempt via HTTP POST Request
    description: Detects potential exploitation attempts of CVE-2025-53521 by monitoring for suspicious HTTP POST requests to BIG-IP APM.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On March 28, 2026, F5 issued a revised security advisory regarding CVE-2025-53521, a vulnerability affecting BIG-IP APM. Initially disclosed in October 2025 and categorized as a medium-severity denial-of-service (DoS) issue, it has been reclassified as a critical remote code execution (RCE) vulnerability. F5 has confirmed that CVE-2025-53521 is now being actively exploited by unauthenticated attackers. The updated classification significantly elevates the risk associated with this…
