---
title: TypeORM SelectQueryBuilder SQL Injection Vulnerability
slug: 2026-08-typeorm-sql-injection
description: TypeORM is vulnerable to SQL injection via the SelectQueryBuilder.distinctOn method due to improper input validation and escaping, allowing for unauthorized data exfiltration through injected subqueries.
date: "2026-08-24T18:03:44Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TypeORM
products:
  - TypeORM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that forwards a client-controlled value into distinctOn, for instance to let a caller choose a deduplication column, allows that client to read data anywhere the application's database role can reach
    confidence_band: high
cves:
  - id: CVE-2026-76848
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76848
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit codebase for use of SelectQueryBuilder.distinctOn with untrusted input
      owner: Application Security
      due: 48h
      evidence: Source describes the vulnerability location in SelectQueryBuilder.ts
---

TypeORM is susceptible to SQL injection (CVE-2026-76848) within its SelectQueryBuilder.distinctOn method when utilizing PostgreSQL-family database drivers. The underlying vulnerability exists in src/query-builder/SelectQueryBuilder.ts, where the createSelectDistinctExpression function joins and interpolates user-provided array elements directly into a SQL statement. Unlike other methods in the query builder that utilize identifier validation or driver-specific escaping, distinctOn bypasses these security controls, including the allowlist checks used by orderBy. 

When an application allows client-controlled data to be passed into distinctOn, an attacker can supply arbitrary SQL fragments, including correlated subqueries. This provides a mechanism for attackers to perform blind SQL injection, exfiltrating data the application's database role can access through boolean or time-based inference. Because this occurs within a parenthesized SQL expression list, the impact is significant for any Node.js application relying on TypeORM for database interactions that dynamically handles query parameters from user inputs.

## Impact

The vulnerability allows unauthorized access to data stored in the database, potentially leading to full information disclosure if the application database role has sufficient permissions. An attacker can use this flaw to exfiltrate data from any reachable table by observing the timing or boolean responses of the application. This affects any application using TypeORM that dynamically generates distinct-on clauses based on untrusted user input.

## Recommendation

- Audit all occurrences of SelectQueryBuilder.distinctOn in the codebase to identify instances where user-controlled input is passed directly to the function.
- Implement strict input validation or mapping to a static allowlist of column names before passing values to distinctOn.
- Upgrade TypeORM to a patched version once released by the maintainers that ensures input sanitization or proper escaping within the distinctOn method.
- Review database role permissions to ensure the application follows the principle of least privilege, minimizing the blast radius of a successful SQL injection attack.
