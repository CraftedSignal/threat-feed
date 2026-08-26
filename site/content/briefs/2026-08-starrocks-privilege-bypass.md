---
title: StarRocks Privilege Bypass in Legacy Materialized View Deletion
slug: 2026-08-starrocks-privilege-bypass
description: A privilege escalation vulnerability (CVE-2026-80346) in StarRocks allows any authenticated user to drop legacy synchronous materialized views without required authorization checks.
date: "2026-08-26T22:24:21Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - StarRocks
products:
  - StarRocks
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any authenticated account can therefore drop a legacy synchronous materialized view belonging to any database, holding no grant on the view, the base table or the database, and the drop is indistinguishable from an authorized one.
    confidence_band: high
cves:
  - id: CVE-2026-80346
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80346
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review and restrict access to all StarRocks clusters to authenticated users with documented business needs
      owner: Security Operations
      due: 48h
      evidence: Any authenticated account can therefore drop a legacy synchronous materialized view
  mitigation_plan:
    - priority: immediate
      action: Patch StarRocks environment to address CVE-2026-80346
      owner: IT Operations
      addresses: CVE-2026-80346
      evidence: NVD vulnerability disclosure
---

StarRocks contains a critical privilege escalation vulnerability, tracked as CVE-2026-80346, affecting the authorization logic for dropping legacy synchronous materialized views. Within the StarRocks codebase, most statement types are routed through the `AuthorizerStmtVisitor` to enforce access controls before execution. However, the `visitDropMaterializedViewStatement` method bypasses this mechanism for legacy synchronous views.

Because legacy synchronous materialized views are stored as rollup indexes within an `OlapTable` object rather than as standalone `MaterializedView` objects, the system fails to trigger the `Authorizer.checkMaterializedViewAction` logic. Instead, the process proceeds through `AlterJobMgr.processDropMaterializedView` and `MaterializedViewHandler`, neither of which contains authorization checks. Consequently, any authenticated user can successfully execute a command to drop a legacy synchronous materialized view in any database, regardless of their actual permission set. This issue presents a significant availability risk, as an attacker can silently remove materialized views, causing downstream query failures and data inconsistencies.

## Impact

Successful exploitation allows any authenticated account to delete legacy materialized views belonging to any database, despite lacking the necessary grants on the views, the underlying base tables, or the target databases. This results in unauthorized data modification and potential service disruption for users relying on those views for reporting or query performance.

## Recommendation

Prioritize patching StarRocks to a version where privilege checks are correctly implemented in `MaterializedViewHandler` for legacy objects. In the interim, restrict access to the StarRocks environment to strictly authorized users, as any authenticated account currently possesses the ability to drop these materialized views. Audit current database schemas to identify all legacy synchronous materialized views to assess the potential impact of potential deletion attempts.
