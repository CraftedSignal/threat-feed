---
title: Authorization Bypass in SurrealDB HTTP Session Construction
slug: 2026-09-surrealdb-auth-bypass
description: SurrealDB versions before 3.3.0 contain an authorization bypass vulnerability where improper namespace and database header validation allows authenticated users to perform unauthorized cross-tenant data operations.
date: "2026-09-29T20:29:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:surrealdb:surrealdb:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cve-2026-102876
  - surrealdb
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: The authorization bypass allows authenticated attackers to perform unauthorized cross-tenant data operations.
    confidence_band: high
cves:
  - id: CVE-2026-102876
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102876
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all SurrealDB instances to version 3.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-102876 patch requirements
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 3.3.0
      owner: IT Operations
      addresses: CVE-2026-102876
      evidence: NVD vulnerability details
---

SurrealDB versions prior to 3.3.0 are susceptible to an authorization bypass vulnerability within the HTTP session construction logic. The vulnerability originates from a flaw in the `check_auth()` process, which verifies user credentials against the `Surreal-Auth-NS` and `Surreal-Auth-DB` headers but fails to validate these credentials against the requested target namespace and database defined in the `Surreal-NS` and `Surreal-DB` headers. 

This logic gap permits an authenticated user to craft HTTP requests that authenticate them successfully against their own tenant space, while simultaneously directing the application to perform read, create, or modify operations on the database and namespace of an entirely different tenant. Because the application trusts the session namespace/database headers without secondary access control verification, this flaw facilitates horizontal and potentially vertical privilege escalation across tenant boundaries. Defenders should prioritize updating to version 3.3.0 to enforce strict header-to-credential validation.

## Impact

Successful exploitation allows an authenticated attacker to bypass tenant isolation controls, resulting in unauthorized access to sensitive data and the ability to manipulate records across the target organization's infrastructure. This vulnerability poses a high risk to multi-tenant environments where data integrity and confidentiality between distinct tenants are critical security requirements.

## Recommendation

1. Upgrade SurrealDB to version 3.3.0 or later immediately to patch CVE-2026-102876.
2. Implement strict input validation on HTTP headers `Surreal-NS` and `Surreal-DB` at the network gateway or application firewall layer to ensure they correspond to the authenticated user's authorized scope.
3. Audit access logs for anomalous cross-tenant activity originating from a single authenticated user session.
