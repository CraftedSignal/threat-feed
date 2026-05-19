---
title: SQLFluff Recursive Stack Overflow Vulnerability (CVE-2026-46373)
slug: 2026-05-sqlfluff-dos
description: A maliciously crafted SQL query with excessive nesting can cause a denial of service by exhausting resources when parsed by SQLFluff versions prior to 4.1.0; version 4.1.0 introduces a configurable recursion limit to mitigate this vulnerability.
date: "2026-05-19T20:10:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dos
  - sqlfluff
  - CVE-2026-46373
products:
  - sqlfluff (< 4.1.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-wmhf-fqc8-vxhh
  - CVE-2026-46373
rules:
  - title: Detect SQLFluff Excessive Recursion Attempt
    description: Detects CVE-2026-46373 exploitation — attempts to exploit SQLFluff's recursive stack overflow by detecting excessively nested SQL queries.
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect SQLFluff Process with High CPU Usage
    description: Detects abnormal CPU usage by sqlfluff processes, potentially indicating a DoS attack (CVE-2026-46373).
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

SQLFluff versions prior to 4.1.0 are vulnerable to a denial-of-service (DoS) attack (CVE-2026-46373) stemming from a recursive stack overflow in the parser. This vulnerability occurs when an untrusted user submits a malicious SQL query containing excessive nesting. The excessive nesting leads to unbounded recursion during parsing, which exhausts system resources and results in a DoS condition. The Imperva Threat Research Team discovered and reported this vulnerability. SQLFluff is commonly used for linting SQL queries, and deployments that allow untrusted users to submit SQL queries for linting are particularly at risk. Version 4.1.0 and later contain a configurable recursion limit, enabled by default, which effectively mitigates this vulnerability.

## Attack Chain

1. An attacker identifies a target application that utilizes SQLFluff for SQL query linting and accepts user-provided SQL queries.
2. The attacker crafts a malicious SQL query with deliberate, excessive nesting of SQL constructs (e.g., nested SELECT statements, subqueries, or deeply nested expressions).
3. The attacker submits the crafted SQL query to the target application.
4. The target application passes the SQL query to SQLFluff for linting.
5. SQLFluff's parser attempts to parse the deeply nested SQL query, leading to uncontrolled recursion.
6. The recursion consumes excessive stack memory and CPU resources.
7. The application's resources become exhausted, leading to a denial-of-service condition.
8. The target application becomes unresponsive or crashes, impacting availability for legitimate users.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the target application unresponsive or unavailable. The severity of the impact depends on the criticality of the affected application and the scale of its user base. While the number of victims is unknown, any system using affected versions of SQLFluff and processing untrusted queries could be impacted. This affects systems where users can supply SQL queries for testing or linting.

## Recommendation

*   Upgrade SQLFluff to version 4.1.0 or later to benefit from the implemented recursion limit, mitigating CVE-2026-46373.
*   Implement input validation and sanitization measures to limit the complexity and depth of user-supplied SQL queries, even if SQLFluff is upgraded.
*   Monitor CPU and memory usage of systems running SQLFluff to detect potential DoS attacks. Deploy the Sigma rule `Detect SQLFluff Excessive Recursion Attempt` to identify suspicious command execution patterns.
*   If upgrading is not immediately feasible, consider implementing a rate-limiting mechanism to restrict the number of SQL query submissions from a single user or IP address within a specific timeframe.
