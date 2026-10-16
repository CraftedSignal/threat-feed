---
title: Authorization Bypass in Tandoor Recipes API Endpoints
slug: 2026-10-tandoor-recipes-auth-bypass
description: CVE-2026-59963 allows an authenticated user to bypass object-level authorization and access, share, or exfiltrate private recipes via utility API endpoints.
date: "2026-10-16T20:45:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tandoorrecipes:recipes:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - api-vulnerability
  - data-exposure
vendors:
  - TandoorRecipes
products:
  - recipes (< 2.6.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack works because the endpoints read private recipe files... without object-level authorization.
    confidence_band: high
cves:
  - id: CVE-2026-59963
    cvss: 7.1
references:
  - https://github.com/TandoorRecipes/recipes/security/advisories/GHSA-cqj3-64qw-4w52
  - https://github.com/TandoorRecipes/recipes/releases/tag/2.6.10
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Tandoor Recipes to version 2.6.10 or later
      owner: IT Operations
      due: 24h
      evidence: Fixed in version 2.6.10.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Tandoor Recipes to 2.6.10
      owner: IT Operations
      addresses: CVE-2026-59963
      evidence: Vendor security advisory.
---

CVE-2026-59963 is an authorization bypass vulnerability in Tandoor Recipes versions prior to 2.6.10. The vulnerability exists within the application's recipe utility API endpoints, including those for AI-based imports, file retrieval, external link generation, and share-link creation. An authenticated user who is a member of a shared Space can supply the identifier of another user's private recipe to these endpoints. The application fails to perform necessary object-level authorization checks, allowing the attacker to retrieve private file bytes, send sensitive data to configured external AI providers, or generate public access links for private recipe content. This flaw enables unauthorized access to and potential exposure of sensitive data belonging to other members within the same Space.

## Impact

The vulnerability results in the exposure of private recipe data and sensitive uploaded content to unauthorized users within a shared space or to configured third-party external services. If successful, an attacker can exfiltrate private content or generate public links to previously restricted information. This affects all Tandoor Recipes instances running versions earlier than 2.6.10, posing a risk to data confidentiality for users managing sensitive meal planning and recipe data.

## Recommendation

- Upgrade Tandoor Recipes to version 2.6.10 or later immediately to patch the missing object-level authorization checks.
- Audit logs for the affected API endpoints (api/ai-import/, api/get_recipe_file/, api/get_external_file_link/, api/share-link/) to identify instances where a single user identifier is associated with multiple unexpected recipe IDs within a short timeframe.
- Monitor logs for unauthorized creation of public share links (api/share-link/) by non-owner users within shared Spaces.
