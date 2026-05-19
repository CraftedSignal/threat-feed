---
title: SQLFluff Uncontrolled Resource Consumption Vulnerability (CVE-2026-46374)
slug: 2026-05-sqlfluff-resource-consumption
description: SQLFluff versions prior to 4.2.0 are vulnerable to uncontrolled resource consumption (CVE-2026-46374), allowing an attacker to cause a denial of service by submitting a maliciously crafted, long SQL query.
date: "2026-05-19T20:13:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - resource-exhaustion
  - sqlfluff
vendors:
  - Imperva
products:
  - sqlfluff (< 4.2.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-73jc-5mrq-prw7
  - CVE-2026-46374
rules:
  - title: Detect SQLFluff Excessive Query Length
    description: Detects unusually long SQL queries that might be used to trigger CVE-2026-46374 in SQLFluff. Requires webserver logs if SQLFluff is exposed via HTTP, or application logs if used locally.
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499.002
    data_sources:
      - webserver
  - title: Detect SQLFluff POST Request with Excessive Query Length
    description: Detects unusually long SQL queries submitted via POST requests, potentially indicating an attempt to trigger CVE-2026-46374 in SQLFluff. Requires webserver logs.
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499.002
    data_sources:
      - webserver
rules_count: 2
---

SQLFluff versions before 4.2.0 are susceptible to an uncontrolled resource consumption vulnerability (CVE-2026-46374). This flaw enables an attacker to exhaust system resources by providing a specially crafted, excessively long SQL query to the SQLFluff parser. This can lead to a Denial-of-Service (DoS) condition, impacting applications that rely on SQLFluff for SQL query linting. The vulnerability was reported by Ori Nakar from Imperva Threat Research Team. Version 4.2.0 introduces a configurable parse node limit to mitigate this vulnerability, preventing the parser from processing excessively complex queries. Exploitation requires untrusted users to be able to submit SQL queries for linting.

## Attack Chain

1. An attacker crafts an extremely long and complex SQL query designed to consume excessive resources during parsing.
2. The attacker submits the malicious SQL query to an application that uses a vulnerable version of SQLFluff (prior to 4.2.0) for linting purposes.
3. The application passes the query to the SQLFluff parser.
4. The SQLFluff parser attempts to process the extremely long and complex SQL query.
5. Due to the lack of input validation and resource limits in vulnerable versions, the parser consumes excessive CPU and memory.
6. The application's performance degrades significantly as system resources are exhausted.
7. The application becomes unresponsive or crashes due to the resource exhaustion, leading to a denial-of-service.
8. Legitimate users are unable to access the application or its SQL linting functionality.

## Impact

Successful exploitation of this vulnerability can result in a denial-of-service condition, rendering applications relying on SQLFluff unavailable. The impact is particularly significant in environments where untrusted users can submit arbitrary SQL queries for linting, as it allows malicious actors to easily disrupt service availability. There is no specific victim count available. This affects any environment using SQLFluff prior to version 4.2.0.

## Recommendation

*   Upgrade SQLFluff to version 4.2.0 or later to incorporate the fix for CVE-2026-46374.
*   Implement input validation and sanitization on SQL queries submitted for linting to prevent excessively long or complex queries from reaching the SQLFluff parser.
*   Monitor system resource utilization (CPU, memory) on systems running SQLFluff to detect potential resource exhaustion attacks. Consider deploying the Sigma rule `Detect SQLFluff Excessive Query Length` to identify potentially malicious queries based on their length.
*   Configure the parse node limit in SQLFluff 4.2.0 and later to restrict the resources consumed by the parser when processing complex SQL queries.
