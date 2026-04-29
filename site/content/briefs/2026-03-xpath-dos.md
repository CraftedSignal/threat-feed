---
title: XPath Boolean Expression DoS Vulnerability
slug: 2026-03-xpath-dos
description: A vulnerability in the antchfx/xpath package allows for denial of service via CPU exhaustion by exploiting boolean expressions that evaluate to true, leading to an infinite loop.
date: "2026-03-29T15:19:45Z"
type: coverage
types:
  - coverage
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

A denial-of-service vulnerability exists in the `antchfx/xpath` Go package, specifically in versions prior to 1.3.6. The vulnerability, identified as CVE-2026-32287, stems from the way the `logicalQuery.Select` function handles boolean expressions. When expressions that always evaluate to true, such as "1=1" or "true()", are used as top-level selectors, they can trigger an infinite loop within the function. This results in the affected system consuming 100% of CPU resources, effectively denying service to legitimate users. The vulnerability was published on March 29, 2026, and patched in version 1.3.6.

## Attack Chain

1. An attacker crafts a malicious XPath expression containing a boolean expression that always evaluates to true, such as "1=1" or "true()".
2. The attacker sends this malicious XPath expression to an application that uses the vulnerable `antchfx/xpath` package.
3. The application parses the XPath expression using the `logicalQuery.Select` function.
4. Due to the nature of the expression, the `logicalQuery.Select` function enters an infinite loop.
5. The infinite loop consumes excessive CPU resources.
6. The application becomes unresponsive due to CPU exhaustion.
7. Legitimate users are unable to access the application.
8. The system experiences a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. An affected server or application becomes unresponsive, impacting all users who rely on the service. While the vulnerability does not directly compromise data confidentiality or integrity, it can severely disrupt operations. The number of potential victims depends on the scope and deployment of applications utilizing the vulnerable `antchfx/xpath` package.

## Recommendation

*   Upgrade the `antchfx/xpath` package to version 1.3.6 or later to patch CVE-2026-32287.
*   Deploy the Sigma rule `Detect XPath Boolean Expression DoS Attempt` to identify attempts to exploit this vulnerability.
*   Monitor web server logs for suspicious XPath expressions, particularly those containing "1=1" or "true()", using the `Web Server Log - XPath Boolean Expression` Sigma rule.
