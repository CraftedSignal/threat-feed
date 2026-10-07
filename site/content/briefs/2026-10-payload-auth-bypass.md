---
title: Authorization Bypass in @payloadcms/plugin-multi-tenant
slug: 2026-10-payload-auth-bypass
description: An authorization vulnerability in @payloadcms/plugin-multi-tenant allows authenticated users to assign themselves to unauthorized tenants by leveraging default field access configurations.
date: "2026-10-07T22:49:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:payload:payloadcms_plugin_multi_tenant:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - cms
vendors:
  - Payload
products:
  - '@payloadcms/plugin-multi-tenant (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user could assign themselves to other tenants.
    confidence_band: high
cves:
  - id: CVE-2026-105860
references:
  - https://github.com/advisories/GHSA-p96c-xwx8-3cqj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105860
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development
  immediate_actions:
    - action: Upgrade @payloadcms/plugin-multi-tenant to 3.90.0 or 4.0.0-canary.34
      owner: Development
      due: 48h
      evidence: Source Patches section
  mitigation_plan:
    - priority: immediate
      action: Configure custom tenants arrayFieldAccess.create/update functions to restrict membership modification
      owner: Application Security
      addresses: CVE-2026-105860
      evidence: Source Workarounds section
---

The Payload Multi-Tenant plugin contains an authorization bypass vulnerability (CVE-2026-105860) that permits authenticated users to manipulate tenant assignments. The vulnerability exists within the default tenant array field access configuration. By default, the plugin lacks sufficient restrictions on the 'create' and 'update' functions for the tenants array field, allowing a standard user to modify their own tenant membership. An attacker could exploit this to gain unauthorized access to other tenants, leading to horizontal or vertical privilege escalation. The issue is resolved in version 3.90.0 and version 4.0.0-canary.34. Organizations using the plugin must ensure they implement custom `arrayFieldAccess` configurations if they cannot upgrade immediately to enforce proper membership validation.

## Impact

Successful exploitation allows an authenticated user to gain access to tenants they are not authorized to manage or view. This results in unauthorized data access and potential privilege escalation within the multi-tenant application environment.

## Recommendation

- Upgrade `@payloadcms/plugin-multi-tenant` to version 3.90.0 or later, or 4.0.0-canary.34 or later to address CVE-2026-105860.
- If upgrading is not immediately feasible, configure custom `tenants arrayFieldAccess.create` and `tenants arrayFieldAccess.update` functions to restrict modifications to users explicitly authorized for all relevant tenants.
