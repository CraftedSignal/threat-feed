---
title: SQLParse CPU Denial of Service via Algorithmic Complexity
slug: 2026-08-sqlparse-dos
description: A complexity vulnerability in sqlparse <= 0.5.5 allows attackers to trigger CPU exhaustion through deeply nested SQL structures, achieving significant amplification and causing denial of service in downstream applications.
date: "2026-08-17T18:46:25Z"
lastmod: "2026-08-17T18:46:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - algorithmic-complexity
  - sqlparse
  - cve-2026-54284
  - denial-of-service
  - vulnerability
products:
  - sqlparse (<= 0.5.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can exploit this by providing a small, crafted SQL payload (1-2 KB) to trigger severe CPU exhaustion, achieving a ~5000x CPU-to-input amplification.
    confidence_band: high
cves:
  - id: CVE-2026-54284
references:
  - https://github.com/advisories/GHSA-pwgv-4x5q-6m9f
  - https://github.com/andialbrecht/sqlparse/blob/0.5.5/sqlparse/sql.py#L162
  - https://github.com/advisories/GHSA-f2ff-p2ww-7p4p
  - https://github.com/andialbrecht/sqlparse/blob/f80af6a4007f11ada847218df8c29dc859238290/sqlparse/engine/grouping.py#L332
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade sqlparse library to the patched version.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends updating to mitigate CVE-2026-54284.
  mitigation_plan:
    - priority: immediate
      action: Implement request timeout and complexity monitoring on endpoints parsing user-supplied SQL.
      owner: Application Security
      addresses: CVE-2026-54284
      evidence: The parser locks workers for up to 10 seconds; timeouts will prevent worker pool exhaustion.
updates:
  - at: "2026-08-17T18:46:40Z"
    level: L1
    summary: added coverage for sqlparse (<= 0.5.5)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-f2ff-p2ww-7p4p
---

The Python library `sqlparse` (version 0.5.5 and earlier) is vulnerable to an algorithmic complexity denial-of-service (DoS) attack. The vulnerability exists within `TokenList.__init__`, which performs an eager, recursive flattening of the SQL subtree (via `str(self)`) during the construction of every token group. 

When `sqlparse` processes input containing deeply nested structures such as parentheses, `CASE WHEN` chains, or nested subqueries, the parser performs work proportional to `O(n*d)` (where `n` is the number of tokens and `d` is the nesting depth). This results in a massive CPU amplification - approximately 5000x for a ~2 KB payload - that consumes significant CPU time before reaching the library's built-in depth and token caps. An attacker can exhaust worker pools in multi-threaded web applications or lock up single-threaded services by sending a small number of these crafted malicious SQL payloads. The issue affects any consumer of `sqlparse` that exposes the parser to unauthenticated user input, including formatters, debug toolbars, and metadata analysis tools.

## Attack Chain

1. Attacker identifies a target application utilizing `sqlparse` to process user-supplied SQL queries (e.g., SQL formatters or database debug interfaces).
2. Attacker crafts a malicious 1-2 KB SQL payload containing high levels of nesting, such as `SELECT (((((...)))))` (2000+ levels) or deeply nested `CASE WHEN` branches.
3. Attacker sends multiple parallel HTTP POST requests containing the crafted payload to the vulnerable endpoint.
4. The application triggers `sqlparse.parse()` or `sqlparse.format()` upon receiving the input.
5. The library's `TokenList.__init__` is invoked recursively during grouping, triggering the `O(n*d)` flattening logic.
6. The system enters a high-CPU state while performing recursive flattening, effectively locking the worker process.
7. The application worker remains unresponsive for seconds to tens of seconds per request.
8. Concurrent requests exhaust the available worker pool, resulting in a denial-of-service condition for legitimate users.

## Impact

Successful exploitation leads to resource exhaustion and service unavailability. Observations indicate that a single 2 KB payload can pin a CPU worker at 100% utilization for approximately 10 seconds. In environments with a limited worker pool, a small number of concurrent requests can result in total service outage. Downstream libraries, such as `sql-metadata`, also inherit this vulnerability, extending the impact to any tool using `sqlparse` for internal query analysis.

## Recommendation

1. Immediately upgrade `sqlparse` to a version that implements the patch described in the advisory (replacing eager `str(self)` materialization with concatenation of cached values).
2. Implement request-size limits and payload-structure complexity heuristics at the WAF or reverse proxy level to detect and drop highly nested SQL patterns before they reach the application.
3. Ensure application-level timeouts are configured for all database-related processing functions to prevent worker-pool starvation from slow-running parser tasks.
4. Review internal usage of `sqlparse` in debug toolbars or log formatters to ensure untrusted user input is not passed directly to library entry points without sanitization or strict depth validation.
