---
title: XPath Boolean Expression DoS Vulnerability
slug: 2026-03-xpath-dos
description: A vulnerability in the antchfx/xpath package allows for denial of service via CPU exhaustion by exploiting boolean expressions that evaluate to true, leading to an infinite loop.
date: "2026-03-29T15:19:45Z"
severities:
  - high
tags:
  - xpath
  - denial-of-service
  - cve-2026-32287
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-65xw-vw82-r86x
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32287
rules:
  - title: Detect XPath Boolean Expression DoS Attempt
    description: Detects attempts to trigger the XPath boolean expression denial-of-service vulnerability by identifying suspicious XPath expressions.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
  - title: Web Server Log - XPath Boolean Expression
    description: Detects potentially malicious XPath boolean expressions in web server logs.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in the `antchfx/xpath` Go package, specifically in versions prior to 1.3.6. The vulnerability, identified as CVE-2026-32287, stems from the way the `logicalQuery.Select` function handles boolean expressions. When expressions that always evaluate to true, such as "1=1" or "true()", are used as top-level selectors, they can trigger an infinite loop within the function. This results in the affected system consuming 100% of CPU resources, effectively denying…
