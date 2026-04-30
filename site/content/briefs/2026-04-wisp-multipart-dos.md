---
title: Wisp Multipart Parsing Vulnerability Leads to Denial of Service
slug: 2026-04-wisp-multipart-dos
description: A vulnerability in the multipart parsing logic of gleam-wisp allows an unauthenticated attacker to bypass request size limits and cause a denial of service by exhausting server memory or disk.
date: "2026-04-03T03:40:30Z"
type: advisory
types:
  - advisory
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

An unauthenticated denial-of-service vulnerability exists in gleam-wisp versions prior to 2.2.2 due to a flaw in the multipart form parsing logic. Specifically, the issue arises from the handling of multipart data within the `multipart_body` and `multipart_headers` functions. The vulnerability stems from the parser's failure to properly decrement the quota when handling chunks that do not contain the multipart boundary, effectively allowing attackers to send arbitrarily large multipart bodies without triggering configured size limits. This results in uncontrolled resource consumption, potentially leading to memory or disk exhaustion. Any application leveraging `require_form` or `require_multipart_form` on user-controlled input is susceptible to this vulnerability.

## Attack Chain

1. An unauthenticated attacker sends an HTTP request to a wisp-based application that uses `require_form` or `require_multipart_form`.
2. The request contains a multipart body crafted to exploit the parsing vulnerability.
3. The multipart body is split into multiple chunks, none of which (except the last) contain the multipart boundary.
4. The `multipart_body` or `multipart_headers` functions in wisp process the initial chunks.
5. The parser recurses due to the `MoreRequiredForBody` or `MoreRequiredForHeaders` branch being triggered, but it does not decrement the quota.
6. The server accumulates the data from these chunks in memory (for form fields) or on disk (for file uploads).
7. The final chunk, containing the boundary, is processed, and only its size is accounted for in the quota.
8. The accumulated data exceeds available memory or disk space, causing a denial of service, application crash, or system termination.

## Impact

This vulnerability can lead to a denial-of-service condition. Successful exploitation allows an unauthenticated attacker to exhaust server resources, rendering the application unavailable. The impact includes potential memory exhaustion or disk exhaustion, leading to application crashes or termination by the operating system. The number of potential victims depends on the adoption of the vulnerable gleam-wisp library.

## Recommendation

*   Apply the fix by upgrading to wisp version 2.2.2 or later to remediate CVE-2026-32145.
*   Deploy a reverse proxy (such as nginx or HAProxy) in front of the application and enforce request body size limits as a workaround to mitigate the vulnerability.
*   Implement monitoring for excessive memory or disk usage by wisp-based applications to detect potential exploitation attempts.
