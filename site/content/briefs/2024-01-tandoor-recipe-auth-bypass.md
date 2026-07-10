---
title: Tandoor Recipes Authentication Bypass Vulnerability (CVE-2026-35045)
slug: 2024-01-tandoor-recipe-auth-bypass
description: Tandoor Recipes before version 2.6.4 allows authenticated users within a space to modify any recipe in that space, including private ones, via the PUT /api/recipe/batch_update/ endpoint, bypassing object-level authorization checks and enabling unauthorized access and data tampering.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - web-application
  - tandoor-recipes
vendors:
  - Tandoor Recipes
products:
  - Tandoor Recipes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35045
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35045
rules:
  - title: Detect Tandoor Recipe Batch Update
    description: Detects PUT requests to the /api/recipe/batch_update/ endpoint in Tandoor Recipes, which is used to exploit CVE-2026-35045.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Tandoor Recipe API Access
    description: Detects any access to the Tandoor Recipe API endpoints, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tandoor Recipes, an application for managing recipes, planning meals, and building shopping lists, contains an authentication bypass vulnerability. Specifically, versions prior to 2.6.4 are susceptible to CVE-2026-35045. This flaw enables any authenticated user within a shared Space to modify any recipe within that Space, regardless of the recipe's privacy settings. The vulnerability stems from a lack of object-level authorization checks on the `/api/recipe/batch_update/` endpoint, contrasting with the more restrictive single-recipe endpoints (PUT `/api/recipe/{id}/`). This allows attackers to force the exposure of private recipes, grant themselves unauthorized access, and tamper with recipe metadata. Defenders should prioritize upgrading Tandoor Recipes to version 2.6.4 to remediate this vulnerability.

## Attack Chain

1. An attacker authenticates to a Tandoor Recipes instance.
2. The attacker identifies a Space containing recipes they wish to modify, including private recipes.
3. The attacker crafts a `PUT` request to the `/api/recipe/batch_update/` endpoint.
4. The request includes a payload designed to modify the target recipe (e.g., changing the recipe name, ingredients, or privacy settings).
5. The application, lacking proper authorization checks on this endpoint, processes the request.
6. The target recipe is modified according to the attacker's specifications, bypassing intended privacy restrictions.
7. The attacker can then exfiltrate or further manipulate the recipe data.

## Impact

Successful exploitation of CVE-2026-35045 can lead to the unauthorized disclosure of private recipes, potentially containing sensitive personal information or proprietary culinary techniques. It can also facilitate the tampering of recipe data, leading to incorrect or malicious instructions. This vulnerability affects all Tandoor Recipes instances running versions prior to 2.6.4 and accessible to authenticated users.

## Recommendation

*   Upgrade Tandoor Recipes to version 2.6.4 or later to patch CVE-2026-35045.
*   Implement the Sigma rule `Detect Tandoor Recipe Batch Update` to monitor for suspicious requests to the `/api/recipe/batch_update/` endpoint.
*   Review webserver access logs for unusual PUT requests targeting the `/api/recipe/batch_update/` endpoint after authentication, to identify possible exploitation attempts.
