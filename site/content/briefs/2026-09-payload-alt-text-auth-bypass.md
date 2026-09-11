---
title: Authorization Bypass in @jhb.software/payload-alt-text-plugin
slug: 2026-09-payload-alt-text-auth-bypass
description: The @jhb.software/payload-alt-text-plugin v0.7.0 fails to restrict Payload Local API calls, allowing authenticated users to bypass collection-level access controls to read and modify document data.
date: "2026-09-11T00:54:16Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - authorization-bypass
  - cms-plugin
  - cwe-863
vendors:
  - jhb.software
products:
  - payload-alt-text-plugin (< 0.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any authenticated user—regardless of role—can read and overwrite the alt and keywords fields of arbitrary upload documents that would otherwise be protected by restrictive collection access rules.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: Because Payload's internal logic evaluates shouldOverrideAccess = overrideAccess !== false, omitting the parameter causes it to default to true, silently bypassing all collection-level access control functions.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4qpv-39hg-f7fx
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @jhb.software/payload-alt-text-plugin to 0.7.1 or later.
      owner: IT Operations
      due: 48h
      evidence: Plugin version 0.7.1 addresses the Local API overrideAccess omission.
  mitigation_plan:
    - priority: immediate
      action: Review access control configurations for all upload collections integrated with the plugin.
      owner: IT Operations
      addresses: CWE-863
      evidence: The vulnerability affects all default deployments where the plugin is enabled.
---

The @jhb.software/payload-alt-text-plugin version 0.7.0 contains an authorization bypass vulnerability affecting how it interacts with the Payload CMS Local API. When performing `findByID` and `update` operations, the plugin fails to explicitly set the `overrideAccess` parameter to `false`. By default, Payload's internal logic interprets the absence of this parameter as `true`, effectively disabling collection-level access control checks.

This flaw allows any authenticated user - regardless of their assigned role - to access or modify restricted upload collections. An attacker can read the content of protected upload documents and overwrite critical fields like `alt` and `keywords`. The vulnerability is critical for environments that rely on Payload's access control features to manage document permissions. The impact is categorized as an Incorrect Authorization (CWE-863) issue.

## Attack Chain

1. Attacker establishes a valid, low-privileged user session within the Payload CMS environment.
2. Attacker identifies a target upload collection that is meant to be restricted to administrative roles.
3. Attacker crafts a POST request targeting the plugin's `/api/alt-text-plugin/generate` or `/bulk` endpoints.
4. Attacker includes specific JSON parameters (`id`, `collection`, `locale`) to target a protected document.
5. The plugin receives the request and executes a Payload Local API call without setting `overrideAccess: false`.
6. Payload CMS internal logic defaults `overrideAccess` to `true`, bypassing all defined `read` or `update` access control functions for the collection.
7. The plugin reads or modifies the protected `alt` and `keywords` fields on behalf of the attacker.
8. Attacker successfully exfiltrates data or alters metadata in documents they are not authorized to access.

## Impact

The vulnerability allows unauthorized read/write access to sensitive metadata within restricted upload collections. An attacker can modify `alt` text and keywords for any document, potentially poisoning content, bypassing organizational access policies, or exfiltrating document metadata that should be restricted based on user role assignments.

## Recommendation

Prioritize the upgrade of `@jhb.software/payload-alt-text-plugin` to version 0.7.1 or later, where the `overrideAccess` parameter is correctly set. For teams unable to patch immediately, implement a custom server-side guard to validate that the `req.user` role has the necessary permissions for the target collection before the request reaches the plugin handler.
