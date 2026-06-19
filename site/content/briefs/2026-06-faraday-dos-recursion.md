---
title: 'Faraday: Uncontrolled Recursion in NestedParamsEncoder Allows Stack Exhaustion DoS'
slug: 2026-06-faraday-dos-recursion
description: An unauthenticated attacker can trigger a denial-of-service condition in applications using the Faraday Ruby library by sending deeply nested query parameters (CVE-2026-54297), leading to `SystemStackError` and application crashes due to uncontrolled recursion.
date: "2026-06-19T20:02:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - web-vulnerability
  - ruby
  - faraday
  - ghsa
  - cve
vendors:
  - Faraday Project
products:
  - Faraday (<= 2.14.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-98m9-hrrm-r99r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54297
rules:
  - title: Detects CVE-2026-54297 Exploitation - Deeply Nested Faraday Query Parameters
    description: Detects exploitation attempts against CVE-2026-54297 by identifying HTTP requests with excessively deeply nested query parameters in Faraday, leading to a denial-of-service condition.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect SystemStackError in Application Logs Indicating DoS
    description: 'Detects the ''SystemStackError: stack level too deep'' message in application logs, which can indicate a denial-of-service condition like the one caused by CVE-2026-54297 in Ruby applications using Faraday.'
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - application_log
      - linux
rules_count: 2
---

The `Faraday::NestedParamsEncoder` component within the Faraday Ruby HTTP client library, affecting versions up to `2.14.2`, contains a critical vulnerability (CVE-2026-54297) that allows for a denial-of-service (DoS) attack. This vulnerability stems from uncontrolled recursion in its `dehash` routine when processing deeply nested query parameters, such as `a[x][x][x]...[x]=1`. An attacker can send a specially crafted, relatively small (around 9.4 KB) HTTP request containing such a query string to an application that utilizes Faraday for parsing or building URLs. This input causes the Ruby process to build an excessively deep `Hash` structure, exhausting the call stack and leading to a `SystemStackError`, effectively crashing the calling thread or worker. This issue impacts the availability of affected applications and does not require authentication or user interaction to exploit.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP request containing an excessively deeply nested query parameter, for example, `GET /search?a[x][x][x]...[x]=1 HTTP/1.1`.
2.  The vulnerable application receives the HTTP request and, as part of its processing, passes the attacker-controlled query string to a Faraday function like `Faraday::Utils.parse_nested_query` or `conn.build_url`.
3.  Faraday's `NestedParamsEncoder`, specifically the `dehash` internal routine, begins recursively processing the deeply nested query parameter structure.
4.  Due to the absence of a maximum nesting depth limit within the `dehash` function, the recursion depth is solely controlled by the attacker's input.
5.  The deep recursion exhausts the Ruby process's call stack.
6.  The Ruby interpreter raises an uncaught `SystemStackError` (indicating "stack level too deep").
7.  The `SystemStackError` causes the application's calling thread or worker to crash, leading to a denial-of-service condition for that specific process or the entire application.

## Impact

Successful exploitation of CVE-2026-54297 results in a denial-of-service against the targeted application. A small, crafted query string of approximately 9.4 KB can trigger a `SystemStackError` in the Ruby runtime, crashing the process or thread handling the request. Repeated requests with such payloads can lead to a prolonged outage for any application that exposes Faraday's parameter parsing or URL-building paths to untrusted input. The vulnerability does not allow for remote code execution, authentication bypass, or data disclosure; its confirmed impact is limited to availability loss.

## Recommendation

*   **Upgrade Faraday:** Immediately upgrade the Faraday gem to a patched version once available. Monitor the official Faraday GitHub repository and RubyGems for security advisories and releases addressing CVE-2026-54297.
*   **Implement web application firewall (WAF) rules:** Deploy WAF rules to detect and block HTTP requests containing an excessive number of `[x]` or similar nested array/hash markers in query parameters, as indicated in the `Detects CVE-2026-54297 exploitation` Sigma rule.
*   **Application-level input validation:** Implement strict input validation in applications that utilize Faraday to parse or build URLs from external input, specifically limiting the maximum depth of nested query parameters.
*   **Deploy the Sigma rules in this brief to your SIEM:** Tune the `Detects CVE-2026-54297 exploitation` rule for your environment to identify attempts to exploit this vulnerability.
