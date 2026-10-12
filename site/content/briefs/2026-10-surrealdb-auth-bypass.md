---
title: Authorization Bypass in SurrealDB via JSON Patch
slug: 2026-10-surrealdb-auth-bypass
description: SurrealDB versions prior to 3.3.0 are vulnerable to an authorization bypass that allows users with table-level write permissions to leak restricted field data through manipulated JSON Patch operations.
date: "2026-10-12T18:35:44Z"
lastmod: "2026-10-12T18:35:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:surrealdb:surrealdb:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - database-security
  - information-disclosure
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: SurrealDB before 3.3.0 allows cross-tenant access because the SurrealQL USE statement switches a session to any namespace/database without checking that the caller's authenticated level covers it.
    confidence_band: high
cves:
  - id: CVE-2026-109341
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109341
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109343
updates:
  - at: "2026-10-12T18:35:52Z"
    level: L2
    summary: added coverage for SurrealDB (< 3.3.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109343
---

SurrealDB before version 3.3.0 contains an authorization bypass vulnerability (CVE-2026-109341) affecting systems that rely on table-level permissions to restrict field access. The flaw allows authenticated users who possess standard write permissions on a table to circumvent SELECT-level restrictions. By submitting crafted JSON Patch operations - specifically 'copy' or 'move' commands - callers can force the application to resolve pointers against unreduced records. This behavior permits the exfiltration of sensitive data that should be protected. Furthermore, attackers may abuse 'test' operation mismatch errors as a side-channel disclosure oracle to infer the contents of hidden fields. This vulnerability poses a significant risk to data confidentiality in multi-tenant or role-based environments where granular field-level access control is enforced.

## Impact

Successful exploitation allows unauthorized users to read sensitive data from restricted fields, leading to information disclosure. The vulnerability affects all deployments of SurrealDB prior to version 3.3.0. Organizations relying on field-level security within SurrealDB are at risk of data leakage if internal or third-party users have table-level write access.

## Recommendation

* Upgrade all SurrealDB instances to version 3.3.0 or later immediately to patch CVE-2026-109341.
* Audit database permissions to ensure that write access is strictly limited to trusted principals until the upgrade is completed.
* Monitor database query logs for suspicious use of JSON Patch 'copy', 'move', or 'test' operations initiated by users who should not have access to sensitive fields.
