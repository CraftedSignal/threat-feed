---
title: Tinyproxy HTTP Chunked Encoding Integer Overflow Denial of Service
slug: 2026-03-tinyproxy-dos
description: An integer overflow vulnerability in Tinyproxy's HTTP chunked transfer encoding parser (versions <= 1.11.3) allows an unauthenticated remote attacker to cause a denial of service by sending a crafted chunk size that bypasses validation, leading to resource exhaustion.
date: "2026-03-30T08:16:17Z"
severities:
  - high
tags:
  - tinyproxy
  - denial-of-service
  - integer-overflow
  - cve-2026-3945
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3945
rules:
  - title: Detect Suspiciously Large HTTP Chunk Size
    description: Detects HTTP requests with abnormally large chunk sizes, potentially indicating exploitation of CVE-2026-3945.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Requests with Large Chunk Sizes via Content Length
    description: Detects HTTP requests that utilize chunked transfer encoding and also set a content length header, which is unusual and may indicate malicious intent.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tinyproxy, a lightweight HTTP/HTTPS proxy daemon, is vulnerable to an integer overflow in its chunked transfer encoding parser. This vulnerability, identified as CVE-2026-3945, affects versions up to and including 1.11.3. A remote, unauthenticated attacker can exploit this flaw by sending a specially crafted HTTP request containing an invalid chunk size value, such as 0x7fffffffffffffff. The `strtol()` function is used to parse chunk sizes but fails to properly validate overflow conditions…
