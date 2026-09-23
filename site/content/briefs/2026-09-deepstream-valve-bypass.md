---
title: deepstream Valve Permission System Bypass via PATCH_MULTI
slug: 2026-09-deepstream-valve-bypass
description: The deepstream server contains a vulnerability where the PATCH_MULTI action is missing from the Valve permission system's rule map, resulting in an unconditional allow for any authenticated user to perform unauthorized record writes.
date: "2026-09-23T01:59:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:deepstream:server:10.1.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authorization-bypass
  - cve-2026-63116
vendors:
  - deepstream
products:
  - deepstream/server (v10.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
    evidence: The PATCH_MULTI action allows unauthorized record writes, bypassing Valve permission systems.
    confidence_band: high
cves:
  - id: CVE-2026-63116
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-89vx-jh4q-vg3w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63116
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade deepstream/server to 10.1.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory states the version 10.1.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Manually register PATCH_MULTI in RULES_MAP if upgrade is delayed
      owner: Security Engineering
      addresses: CVE-2026-63116
      evidence: Suggested fix provided in GHSA advisory
---

Deepstream servers using the Valve (ConfigPermission) permission system are vulnerable to an authorization bypass due to a configuration oversight in the `src/services/permission/valve/rules-map.ts` file. The `RECORD_ACTION.PATCH_MULTI` action, introduced in recent versions, was never registered in the `RULES_MAP` used by the system to evaluate user permissions. 

When the server receives a `PATCH_MULTI` message, the `getRulesForMessage()` function fails to find a corresponding rule mapping and returns `null`. The system's security logic is designed to treat a `null` result as an unconditional allow, effectively bypassing all configured Valve permission rules. This allows any successfully authenticated user, regardless of their defined access level, to write arbitrary data to any record in the system. This vulnerability impacts production environments using the Valve permission model, potentially leading to unauthorized data modification, privilege escalation through record manipulation, and system-wide service disruption.

## Attack Chain

1. Attacker performs authentication against the deepstream server using valid, low-privilege credentials.
2. Attacker crafts a malicious WebSocket message with `topic: RECORD` and `action: PATCH_MULTI`.
3. Attacker specifies a target record name (e.g., "admin/secret-record") and malicious `parsedData` in the message payload.
4. The `message-processor.ts` service receives the request and triggers a permission evaluation call to `ConfigPermission.canPerformAction()`.
5. The permission service invokes `getRulesForMessage()` to retrieve the policy for `PATCH_MULTI`.
6. `getRulesForMessage()` fails to find the action in the `RULES_MAP` and returns `null`.
7. The `config-permission.ts` logic evaluates the `null` result and defaults to an unconditional grant of access.
8. The server performs the record operation, modifying the target resource as requested by the attacker.

## Impact

Successful exploitation allows any authenticated user to bypass all configured security policies, granting them write access to sensitive records and administrative data. Impact includes full data integrity loss, unauthorized privilege escalation if permission records are stored in deepstream, and potential application-level denial of service due to record corruption. Only deployments configured with `permission.type: 'config'` are affected.

## Recommendation

1. Upgrade all instances of `@deepstream/server` to the version containing the fix for CVE-2026-63116.
2. If an immediate upgrade is not possible, apply a manual patch to `src/services/permission/valve/rules-map.ts` to include `[RECORD_ACTION.PATCH_MULTI]: RULE_TYPES.WRITE`.
3. Audit application record logs for suspicious `PATCH_MULTI` operations originating from low-privilege service accounts or users.
4. Implement strict network-level segmentation to limit the reach of authenticated users to internal deepstream management records.
