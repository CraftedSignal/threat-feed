---
title: Wisp Multipart Parsing Vulnerability Leads to Denial of Service
slug: 2026-04-wisp-multipart-dos
description: A vulnerability in the multipart parsing logic of gleam-wisp allows an unauthenticated attacker to bypass request size limits and cause a denial of service by exhausting server memory or disk.
date: "2026-04-03T03:40:30Z"
severities:
  - high
tags:
  - denial-of-service
  - multipart-parsing
  - gleam-wisp
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Resource Hijacking
cves:
  - id: CVE-2026-32145
    epss: 0.00056
references:
  - https://github.com/advisories/GHSA-8645-p2v4-73r2
  - https://github.com/gleam-wisp/wisp/commit/d8e722e22ccb42bda9d0b6248658d37ab4e9b376
  - https://github.com/gleam-wisp/wisp/commit/7a978748e12ab29db232c222254465890e1a4a90
rules:
  - title: Detect Large HTTP Request Bodies via Webserver Logs
    description: Detects abnormally large HTTP request bodies, which can indicate a denial-of-service attempt exploiting the multipart parsing vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple POST Requests to Form Endpoints within Short Timeframe
    description: Detects potential DoS attempts by identifying a high number of POST requests to form-handling endpoints within a short period.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect High Memory Usage by Beam.smp
    description: Detects potential DoS attacks by identifying beam.smp processes exceeding a specified memory threshold, potentially indicating exploitation of CVE-2026-32145.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

An unauthenticated denial-of-service vulnerability exists in gleam-wisp versions prior to 2.2.2 due to a flaw in the multipart form parsing logic. Specifically, the issue arises from the handling of multipart data within the `multipart_body` and `multipart_headers` functions. The vulnerability stems from the parser's failure to properly decrement the quota when handling chunks that do not contain the multipart boundary, effectively allowing attackers to send arbitrarily large multipart bodies…
