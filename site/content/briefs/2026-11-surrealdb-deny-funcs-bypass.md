---
brief_id: brief-2026-11-03-surrealdb-deny-funcs-bypass
event_id: brief-2026-11-03-surrealdb-deny-funcs-bypass
revision: 1
activity_at: "2026-11-03T15:59:37Z"
title: 'SurrealDB: Security capability bypass in streaming engine (CVE-2026-121416)'
slug: 2026-11-surrealdb-deny-funcs-bypass
description: SurrealDB versions 2.0.0 through 3.3.0 fail to enforce --deny-funcs restrictions on method-style function calls, allowing authenticated users to execute forbidden functions and bypass file system access controls.
date: "2026-11-03T15:59:37Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of SurrealDB query logs.
cpes:
  - cpe:2.3:a:surrealdb:surrealdb:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - database
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.3.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated users who can submit queries can run denied functions via method syntax to write and read file bucket data despite file::* denials.
    confidence_band: high
cves:
  - id: CVE-2026-121416
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121416
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all SurrealDB instances to version 3.3.1 or later.
      owner: IT Operations
      due: 48h
      evidence: SurrealDB 2.0.0 before 3.3.1 does not enforce --deny-funcs restrictions.
  hunt_leads:
    - lead: 'Monitor query logs for method-style invocations containing restricted function namespaces like file::'
      technique_id: T1059
      data_needed:
        - SurrealDB application logs
        - Database audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Authenticated users can run denied functions via method syntax, e.g. [1,2].map() or $f.put()/$f.get() to write and read file bucket data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to SurrealDB 3.3.1
      owner: IT Operations
      addresses: CVE-2026-121416
      evidence: SurrealDB 2.0.0 before 3.3.1 does not enforce --deny-funcs restrictions.
---

A security vulnerability exists in the SurrealDB streaming engine where method-style function calls bypass the configured '--deny-funcs' capability restrictions. The vulnerability stems from the 'MethodPart::evaluate' function, which invokes resolved functions without performing necessary capability checks. This allows an authenticated user to perform restricted actions, such as arbitrary file system access using 'file::*' functions, by wrapping them in method-style syntax (e.g., '.map()'). 

## Impact
Successful exploitation allows an authenticated user with query submission privileges to bypass defined system restrictions. This can result in unauthorized reading or writing of data within configured file buckets, effectively neutralizing security controls intended to limit function execution.

## Recommendation
- Update all SurrealDB instances to version 3.3.1 or later to apply the capability check fix.
- Review and audit existing query logs for usage of method-style syntax that attempts to interact with restricted functions (e.g., 'file::' namespaces).
- Restrict query submission privileges to trusted users until the patch is applied.
