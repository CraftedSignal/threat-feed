---
title: JSONata $toMillis Function Vulnerability Leads to Denial of Service (CVE-2026-52746)
slug: 2026-07-jsonata-dos
description: A high-severity vulnerability, CVE-2026-52746, in JSONata versions prior to 2.2.0 allows unauthenticated attackers to cause a denial of service by exploiting superlinear backtracking in the ISO-8601 validation regex through malicious inputs to the `$toMillis` function, leading to resource exhaustion and application unresponsiveness.
date: "2026-07-03T11:29:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - nodejs
  - vulnerability
  - CVE-2026-52746
vendors:
  - JSONata
products:
  - JSONata (< 2.2.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Malicious inputs to the $toMillis function can cause superlinear backtracking in the ISO-8601 validation regex. This may lead to denial of service in applications that evaluate user-provided JSONata expressions.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-86vw-mfpg-wwv9
  - https://github.com/jsonata-js/jsonata/releases/tag/v2.2.0
---

A critical vulnerability, CVE-2026-52746, has been identified in JSONata versions prior to 2.2.0. This flaw enables attackers to initiate a denial of service (DoS) by leveraging specially crafted, non-matching inputs to the `$toMillis` function. These malicious inputs trigger superlinear backtracking within the ISO-8601 validation regex, resulting in significant CPU resource consumption. Applications that evaluate user-provided JSONata expressions are particularly susceptible, as exploitation can render them unresponsive or cause crashes. The issue was disclosed by Doruk Tan Öztürk and has been addressed in JSONata version 2.2.0 through fixes implemented in pull requests #782 and #793. Developers are urged to update their JSONata dependencies immediately to mitigate this risk.

## Attack Chain

1.  **Attacker crafts malicious JSONata expression**: An attacker creates a JSONata expression specifically designed with non-matching inputs for the `$toMillis` function.
2.  **Attacker delivers expression to vulnerable application**: The malicious JSONata expression is submitted to a web application or service that processes user-controlled JSONata queries.
3.  **Vulnerable application evaluates expression**: The application, running an affected JSONata version (`< 2.2.0`), attempts to evaluate the provided expression and validate the `$toMillis` input using its ISO-8601 regex.
4.  **Regex backtracking consumes excessive resources**: The malformed input triggers a superlinear backtracking issue within the ISO-8601 validation regex, leading to a significant increase in the application's CPU utilization.
5.  **Application becomes unresponsive**: Due to the consumed resources, the application experiences a denial of service, becoming slow, unresponsive, or crashing entirely.

## Impact

Successful exploitation of CVE-2026-52746 results in a denial of service (DoS) condition for applications utilizing vulnerable JSONata versions. Affected organizations may experience application unresponsiveness, service outages, and potential data processing interruptions. While no specific victim counts or targeted sectors were provided, any application parsing untrusted JSONata expressions is at risk of resource exhaustion and service disruption.

## Recommendation

*   Immediately upgrade JSONata to version `2.2.0` or newer to patch CVE-2026-52746.
*   Review applications that process user-provided JSONata expressions to ensure they are using patched versions of `npm/jsonata`.
