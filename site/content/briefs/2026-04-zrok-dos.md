---
title: zrok Unauthenticated Denial-of-Service Vulnerability
slug: 2026-04-zrok-dos
description: An unauthenticated attacker can cause a denial-of-service (DoS) in zrok by sending a crafted HTTP request with a large cookie chunk count to an OAuth-protected proxy share, triggering unbounded memory allocation and leading to process termination.
date: "2026-04-17T12:00:00Z"
severities:
  - high
tags:
  - dos
  - vulnerability
  - zrok
  - CVE-2026-40303
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-cpf9-ph2j-ccr9
rules:
  - title: Detect Suspicious Cookie Header Size
    description: Detects HTTP requests with abnormally large Cookie header sizes, potentially indicating a DoS attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple 500 Errors From Zrok Proxy
    description: Detects multiple 500 errors originating from a Zrok proxy server within a short time frame, potentially indicating a DoS condition.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in zrok versions 1.1.11 and earlier, as well as versions 2.0.0 and earlier, due to unbounded memory allocation in the `GetSessionCookie` function. This function, located in `endpoints/oauthCookies.go`, parses an attacker-supplied cookie chunk count and calls `make([]string, count)` without any upper bound before token validation. Since this function is invoked on every request to an OAuth-protected proxy share, an unauthenticated remote attacker can send…
