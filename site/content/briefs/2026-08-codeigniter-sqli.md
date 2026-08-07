---
title: SQL Injection in CodeIgniter4 Query Builder deleteBatch Method
slug: 2026-08-codeigniter-sqli
description: A SQL injection vulnerability in CodeIgniter4 (CVE-2026-63221) allows unauthenticated attackers to execute arbitrary SQL via improperly handled where() clauses when using the deleteBatch() method.
date: "2026-08-07T21:30:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-vulnerability
  - sqli
  - codeigniter4
vendors:
  - CodeIgniter
products:
  - CodeIgniter4 Framework
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A SQL injection vulnerability exists in the Query Builder's deleteBatch() method... allowing SQL injection.
    confidence_band: high
cves:
  - id: CVE-2026-63221
    cvss: 9.4
    epss: 0.00377
references:
  - https://github.com/advisories/GHSA-c9w5-rwh3-7pm9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63221
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Patch CodeIgniter4 Framework to version 4.7.4 or higher
      owner: IT Operations
      due: 24h
      evidence: Upgrade to v4.7.4 or later.
---

A critical SQL injection vulnerability (CVE-2026-63221) exists within the CodeIgniter4 framework, specifically affecting the Query Builder's `deleteBatch()` method. When developers utilize `deleteBatch()` in conjunction with `where()` conditions, the framework fails to enforce proper escaping on bound values within the `WHERE` clause. This oversight results in the direct substitution of these values into the generated SQL string. If an application accepts user-supplied input and passes it into a `where()` condition before invoking `deleteBatch()`, an attacker can inject malicious SQL syntax. This vulnerability affects CodeIgniter4 versions from 4.3.0 up to, but not including, 4.7.4. The vulnerability is specific to the `deleteBatch()` execution path, whereas standard `delete()` operations are unaffected. Organizations utilizing CodeIgniter4 should prioritize upgrading to version 4.7.4 or later to remediate this flaw.

## Impact

Successful exploitation allows for arbitrary SQL execution, potentially leading to unauthorized data access, modification, or complete database compromise. This impacts any web application built on the affected versions of CodeIgniter4 that performs batch deletions based on user-supplied criteria.

## Recommendation

- Upgrade to CodeIgniter4 version 4.7.4 or later immediately.
- Audit application code for instances where `deleteBatch()` is used in combination with `where()` clauses that ingest unsanitized user input.
- Implement strict input validation and casting for all parameters passed to `where()` calls if immediate upgrading is not possible.
- Transition user-controlled conditional deletions to use the standard `delete()` method with proper query binding instead of `deleteBatch()`.
- Use `onConstraint()` to define batch matching criteria rather than relying on external `where()` conditions.
