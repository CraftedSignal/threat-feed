---
title: Cross-Tenant IDOR in Laravel Backpack CRUD Write Operations
slug: 2026-08-laravel-backpack-idor
description: Laravel Backpack CRUD fails to enforce query scopes on update, delete, and reorder operations, enabling authenticated users to perform unauthorized actions on records belonging to other tenants or users via CVE-2026-54180.
date: "2026-08-20T19:13:41Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Laravel Backpack
products:
  - Backpack CRUD
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Vulnerability
    evidence: The CRUD panel Update, Delete, and Reorder operations bypassed scopes, fetching records directly from the unscoped model query.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vgmv-8xjc-6rch
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54180
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Patch Laravel Backpack CRUD to v6.8.14 or v7.0.38
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends immediate patch for CVE-2026-54180
  mitigation_plan:
    - priority: immediate
      action: Implement custom Gate or Policy checks in CrudController methods
      owner: Application Security
      addresses: CVE-2026-54180
      evidence: Workaround provided by advisory
---

Laravel Backpack CRUD, a widely used package for the Laravel framework, contains a significant access control vulnerability (CVE-2026-54180) affecting its CRUD panel operations. Specifically, while the package correctly applies query scopes defined through `addClause()` and `addBaseClause()` - commonly used for multi-tenancy or row-level ownership enforcement - during list and read operations, it fails to apply these same scopes during **Update**, **Delete**, and **Reorder** operations.

This disparity results in an Insecure Direct Object Reference (IDOR) vulnerability. Authenticated users who possess or can predict the primary key of a target record can bypass intended access controls to modify, delete, or reorder data they are not authorized to access. This is particularly critical for applications that rely on `addBaseClause()` to isolate user or tenant data. The vulnerability was reported by Vishal Shukla and affects versions 6.x prior to 6.8.14 and 7.x prior to 7.0.38.

## Impact

The vulnerability allows unauthorized manipulation of application data across tenant or user boundaries. Successful exploitation permits low-privilege authenticated users to delete or corrupt records belonging to other users or organizations. The impact is highest in multi-tenant SaaS environments where strict data isolation is a primary security requirement.

## Recommendation

* Upgrade to Backpack CRUD version 6.8.14 or 7.0.38 immediately to restore scope enforcement on write operations.
* For environments unable to patch, implement explicit Laravel `Gate` or `Policy` checks within the `update()`, `destroy()`, and `reorder()` methods of all affected `CrudController` classes to verify user ownership of the target record.
* Audit logs for anomalous CRUD operations occurring against records outside of the expected user session scope.
