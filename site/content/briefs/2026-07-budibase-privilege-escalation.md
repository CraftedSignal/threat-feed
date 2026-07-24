---
title: Budibase Privilege Escalation via Role Assignment API
slug: 2026-07-budibase-privilege-escalation
description: An app-scoped builder in Budibase can exploit a missing authorization flaw in the public role assignment API (`POST /api/public/v1/roles/assign`) to escalate privileges, granting themselves builder access to any other application within the tenant, read/modify data, exfiltrate datasource credentials, and execute arbitrary code via automation steps, compromising the entire tenant's app and data plane in Budibase versions up to and including 3.39.19 and npm/@budibase/server up to 3.38.1.
date: "2026-07-24T21:15:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - budibase
  - privilege-escalation
  - API-abuse
  - authorization-bypass
  - vulnerability
vendors:
  - Budibase
products:
  - Budibase (<= 3.39.19)
  - npm/@budibase/server (<= 3.38.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Budibase versions up to 3.39.19 are vulnerable to a high-severity privilege escalation flaw (...) allowing an app-scoped builder to gain unauthorized builder access to any other application within the tenant.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: assign arbitrary data-plane roles (e.g. ADMIN) in any app to any user, including themselves.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: edit automations (including the `bash`/`executeScript`/`executeQuery` steps)
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: read those apps' datasource configurations and exfiltrate stored datasource credentials
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-j9fc-w3mr-x6mv
---

Budibase versions up to 3.39.19 are vulnerable to a high-severity privilege escalation flaw (GHSA-j9fc-w3mr-x6mv) allowing an app-scoped builder to gain unauthorized builder access to any other application within the tenant. This vulnerability, an an incomplete fix of a previous hardening attempt, stems from a missing authorization check in the `POST /api/public/v1/roles/assign` API endpoint. Attackers can leverage their existing app-scoped builder privileges to self-assign elevated roles or cross-app builder access, leading to a tenant-wide compromise of app data and the potential for remote code execution via automation steps, as well as exfiltration of stored datasource credentials. The flaw impacts licensed Budibase deployments (Business/Enterprise) where `isExpandedPublicApiEnabled` is active.

## Attack Chain

1. An attacker, possessing an app-scoped builder role for `appA` but no global administrative privileges, initiates the attack.
2. The attacker authenticates and sends a `POST` request to the `/api/global/self/api_key` endpoint on the Budibase worker, successfully obtaining a public API key, as app-scoped builders have `hasBuilderPermissions` which passes the `builderOnly` middleware check.
3. Using the newly acquired API key and their session cookie, the attacker sends a `POST` request to `/api/public/v1/roles/assign`, setting the `x-budibase-app-id` header to `appA` (their controlled app ID) and including a JSON body specifying `{"userIds":["<self>"],"appBuilder":{"appId":"<appB>"}}` where `appB` is the target application.
4. The API endpoint's `builderOrAdmin` middleware passes due to `isBuilder(user, appA)`, and the `validateGlobalRoleUpdate` function (designed for global roles) ignores the `appBuilder` attribute, which was not referenced for validation.
5. The `sdk.publicApi.roles.assign` function processes the request, adding `appB` to the attacker's `user.builder.apps` without performing any authorization checks that the caller controls `appB`.
6. The attacker successfully escalates privileges, becoming a builder for `appB` and potentially any other app within the tenant.
7. With builder access to `appB`, the attacker can now read/modify all data rows, access and exfiltrate stored datasource credentials, and modify automations to achieve remote code execution via `bash`, `executeScript`, or `executeQuery` steps, leading to tenant-wide app/data-plane compromise.

## Impact

A successful exploitation of this vulnerability allows an app-scoped builder to bypass cross-app isolation, gaining builder access to all other applications within the licensed Budibase tenant. This enables the attacker to read and modify sensitive data, exfiltrate stored datasource credentials (e.g., database connection strings, API keys), and create or modify automation rules to execute arbitrary code on the server. The attacker can also assign any data-plane role, including `ADMIN`, to themselves or any other user within any application. While it doesn't directly grant global `admin` or `builder` flags, it effectively leads to a tenant-wide compromise of all app data and functionality.

## Recommendation

* Upgrade Budibase deployments to a patched version to remediate the missing authorization checks in the `POST /api/public/v1/roles/assign` endpoint.
* Implement API gateway or WAF rules to inspect and validate requests to the `/api/public/v1/roles/assign` endpoint, specifically checking if the `appId` in the request body matches the `x-budibase-app-id` header for non-global administrators.
* Monitor `webserver` logs for unusual or excessive `POST` requests to `/api/global/self/api_key` and `/api/public/v1/roles/assign` endpoints from non-global administrator accounts, which could indicate attempts to exploit this vulnerability.
