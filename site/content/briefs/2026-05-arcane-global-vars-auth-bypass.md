---
title: Arcane Global Variables Endpoint Missing Admin Authorization Check
slug: 2026-05-arcane-global-vars-auth-bypass
description: A missing admin authorization check in the Arcane application on the `PUT /api/environments/{id}/templates/variables` endpoint allows any authenticated non-admin user to overwrite global environment variables, leading to supply-chain RCE, credential theft, and cross-tenant impact by overriding critical configuration values.
date: "2026-05-23T00:19:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arcane
  - authorization-bypass
  - rce
  - credential-theft
  - supply-chain
vendors:
  - github
products:
  - Arcane
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-jpjh-jm2p-39hh
  - CVE-2026-47125
rules:
  - title: Detect Arcane Global Variable Override via API
    description: Detects CVE-2026-47125 exploitation — modification of Arcane global variables via the API endpoint by non-admin users.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
  - title: Detect Suspicious Characters in Arcane Global Variable Update
    description: Detects suspicious characters in global variable keys during Arcane updates, potentially indicating injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
rules_count: 2
---

The Arcane application, specifically versions 1.19.1 and earlier, contains a critical vulnerability related to the `PUT /api/environments/{id}/templates/variables` endpoint. This endpoint, which writes the system-wide `.env.global` file used for variable substitution in every project's compose file, lacks an admin authorization check. Consequently, any authenticated non-admin user can exploit this flaw by calling the endpoint with their bearer token or API key, effectively overwriting global environment variables that are merged into every project deployment. This oversight can be leveraged to compromise the entire Arcane instance.

## Attack Chain

1. An attacker authenticates to the Arcane application as a non-admin user, obtaining a valid bearer token or API key.
2. The attacker crafts a `PUT` request to the `/api/environments/{id}/templates/variables` endpoint, with a malicious payload in the request body containing environment variables to overwrite.
3. The attacker injects malicious values for critical variables such as `REGISTRY`, `IMAGE`, `DATABASE_URL`, or `SECRET_KEY`. The `key` field can contain embedded newlines to inject arbitrary keys.
4. The Arcane backend processes the request through the `UpdateGlobalVariables` handler in `templates.go`, which fails to perform an admin role check.
5. The `UpdateGlobalVariables` function in `template_service.go` writes the attacker-supplied key-value pairs to the `<projectsDirectory>/.env.global` file, without proper sanitization or validation of the key field.
6. At deploy time, when any project loads its environment variables, the `loadAndMergeGlobalEnv` function in `env.go` reads and merges the attacker-modified `.env.global` file into the project's environment.
7. If `REGISTRY` or `IMAGE` were modified, subsequent deployments will pull attacker-controlled images from a malicious registry, resulting in arbitrary code execution on the Docker host.
8. If `DATABASE_URL` or other sensitive connection strings were modified, applications will connect to attacker-controlled servers, allowing for credential theft and data exfiltration.

## Impact

Successful exploitation of this vulnerability allows a non-admin user to achieve several critical impacts: cross-project supply-chain RCE on the Docker host, credential theft from other users' projects, cross-tenant integrity compromise leading to service disruption, and bypass of the intended privilege boundary. The vulnerability impacts any Arcane instance where non-admin users have access to the API and the instance depends on the global environment variables. Successful exploitation could allow full control of the host system.

## Recommendation

*   Apply the vendor-supplied patch or upgrade to a version of Arcane greater than 1.19.1 to address CVE-2026-47125.
*   Deploy the Sigma rule "Detect Arcane Global Variable Override via API" to detect unauthorized modifications to global environment variables via the vulnerable API endpoint.
*   Enable webserver logging and monitor HTTP requests to the `/api/environments/{id}/templates/variables` endpoint for suspicious activity, particularly PUT requests from non-admin users.
*   Implement robust input validation and sanitization on all user-supplied data, including environment variable keys and values, to prevent injection attacks.
