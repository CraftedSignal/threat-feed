---
title: Cloudreve OAuth Admin.Read Scope Bypass for OneDrive Storage Policy Credential Update (CVE-2026-55502)
slug: 2026-07-cloudreve-oauth-bypass
description: An authorization bypass vulnerability (CVE-2026-55502) in Cloudreve 4.16.1 allows an attacker with an `Admin.Read` OAuth token to modify the OneDrive storage policy credentials via a POST request to `/api/v4/admin/policy/oauth/signin`, despite lacking `Admin.Write` scope, which can break the storage backend and redirect future OAuth setups.
date: "2026-07-24T20:50:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - cloudreve
  - oauth
  - web-vulnerability
  - credential-manipulation
vendors:
  - Cloudreve
products:
  - Cloudreve (v4)
  - Cloudreve (v3)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An OAuth bearer token scoped to `Admin.Read` but not `Admin.Write` can call `POST /api/v4/admin/policy/oauth/signin` and update OneDrive storage policy credentials. ... Its handler persists attacker-supplied `secret` and `app_id` values into the selected OneDrive storage policy...
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hq88-5x99-x3gf
rules:
  - title: Detects CVE-2026-55502 Exploitation - Cloudreve OAuth Admin.Read Bypass
    description: Detects exploitation attempts of CVE-2026-55502 in Cloudreve where an attacker uses a POST request to bypass Admin.Read scope and modify OneDrive policy credentials. This rule flags requests to the vulnerable endpoint.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1098.006
    data_sources:
      - webserver
rules_count: 1
---

A critical authorization bypass vulnerability, identified as CVE-2026-55502, has been discovered in Cloudreve versions < 4.0.0-20260613030954-9e9fb43e7288 and <= 3.0.0-20250225100611-da4e44b74af4. This flaw allows an OAuth bearer token scoped to `Admin.Read`, but explicitly lacking `Admin.Write` permissions, to invoke `POST /api/v4/admin/policy/oauth/signin`. This endpoint is intended for read-only administrative functions but fails to enforce the `Admin.Write` guard present in other sensitive policy mutation routes. Attackers can exploit this to persistently modify the `secret` and `app_id` associated with a configured OneDrive storage policy, potentially disrupting storage services, replacing legitimate application credentials, and redirecting future OAuth configurations to attacker-controlled parameters. The vulnerability highlights a breakdown in scope enforcement within Cloudreve's administrative API.

## Attack Chain

1. A Cloudreve instance is configured with at least one OneDrive storage policy.
2. An administrative user mistakenly or maliciously authorizes an OAuth client for `Admin.Read` scope, but specifically does not grant `Admin.Write` scope.
3. The OAuth client successfully obtains a valid bearer access token for the admin user, constrained to `Admin.Read` permissions.
4. The attacker, leveraging the `Admin.Read` token, crafts and sends an HTTP POST request to the vulnerable endpoint `/api/v4/admin/policy/oauth/signin`.
5. The POST request includes a JSON body containing attacker-controlled values for `id`, `secret` (e.g., "attacker-secret"), and `app_id` (e.g., "attacker-app-id").
6. Due to the absence of the intended `Admin.Write` authorization guard, the Cloudreve application endpoint `controllers.AdminOdOAuthURL` processes the request as if it were authorized.
7. The underlying handler in `service/admin/policy.go` persistently updates the selected OneDrive storage policy by replacing its `SecretKey` and `BucketName` (which maps to `app_id`) with the attacker-supplied values.
8. This action permanently modifies the storage backend configuration, breaking legitimate access, replacing critical application credentials, and redirecting all subsequent OAuth setups for that policy to parameters controlled by the attacker.

## Impact

Successful exploitation of CVE-2026-55502 allows an unauthorized entity, possessing only read-level administrative OAuth access, to achieve significant control over OneDrive storage policies. This can lead to a complete disruption of the affected storage backend, rendering it inaccessible to legitimate users. The attacker can replace the genuine application secret and app ID, effectively hijacking the policy. Consequently, any future attempts to reconfigure or re-authenticate the OneDrive storage will be directed to attacker-controlled OAuth applications, leading to potential data exfiltration, service outages, or further compromise of integrated services. While no specific victim counts are provided, any Cloudreve installation using OneDrive storage policies with improperly scoped OAuth clients is at risk.

## Recommendation

* Patch CVE-2026-55502 immediately by upgrading Cloudreve to a version greater than or equal to 4.0.0-20260613030954-9e9fb43e7288 (for v4) or greater than 3.0.0-20250225100611-da4e44b7af4 (for v3).
* Deploy the Sigma rule in this brief to your SIEM to detect exploitation attempts of CVE-2026-55502 against the `webserver` logs.
* Review web server access logs for any suspicious `POST` requests to `/api/v4/admin/policy/oauth/signin` as identified in the Sigma rule, especially from OAuth clients with only `Admin.Read` scope.
