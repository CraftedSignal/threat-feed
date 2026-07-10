---
title: Tandoor Recipes Unauthorized RecipeBook Modification Vulnerability (CVE-2026-35488)
slug: 2024-01-tandoor-recipe-overwrite
description: Tandoor Recipes versions prior to 2.6.4 allow unauthorized modification and deletion of RecipeBooks due to a flaw in the CustomIsShared permission class which grants write access to shared users regardless of intended read-only permissions.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CVE-2026-35488
  - Tandoor Recipes
  - Unauthorized Access
  - Data Modification
vendors:
  - Tandoor
products:
  - Tandoor Recipes
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
cves:
  - id: CVE-2026-35488
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35488
rules:
  - title: Detect Tandoor RecipeBook Unauthorized Modification
    description: Detects unauthorized modification of Tandoor RecipeBooks by users with shared access based on HTTP PUT requests to the RecipeBook API endpoint.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Tandoor RecipeBook Unauthorized Deletion
    description: Detects unauthorized deletion of Tandoor RecipeBooks by users with shared access based on HTTP DELETE requests to the RecipeBook API endpoint.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tandoor Recipes, a popular application used for managing recipes, planning meals, and building shopping lists, contains a critical vulnerability (CVE-2026-35488) in versions prior to 2.6.4. The vulnerability stems from improper permission handling within the `CustomIsShared` permission class in the `RecipeBookViewSet` and `RecipeBookEntryViewSet`. Specifically, the `has_object_permission()` method incorrectly returns `True` for all HTTP methods, including `DELETE`, `PUT`, and `PATCH`, without validating if the request method is considered a `SAFE_METHODS` (e.g., `GET`, `HEAD`, `OPTIONS`). This oversight allows any user included on the shared list of a `RecipeBook` to not only view but also delete or overwrite the book's contents, even though shared access is semantically intended to be read-only. This poses a significant risk of data loss and unauthorized modification of user data. The vulnerability is addressed in version 2.6.4.

## Attack Chain

1. An attacker gains legitimate access to a Tandoor Recipes instance.
2. A victim creates a RecipeBook and shares it with the attacker.
3. The attacker identifies the API endpoint for RecipeBook modification (e.g., `/api/recipebooks/{id}`).
4. The attacker crafts a malicious HTTP PUT request to modify the RecipeBook, bypassing intended permission checks.
5. The attacker sends the crafted PUT request to the Tandoor Recipes server, including data to overwrite existing recipe information.
6. Alternatively, the attacker crafts a malicious HTTP DELETE request to delete the RecipeBook, also bypassing permission checks.
7. The server processes the unauthorized PUT or DELETE request due to the flawed CustomIsShared permission class.
8. The RecipeBook is either modified with the attacker's data or completely deleted, leading to data loss or corruption for the victim.

## Impact

Successful exploitation of CVE-2026-35488 allows any user with shared access to a RecipeBook to completely overwrite or delete it. This leads to a complete loss of recipe data for the owner and any other shared users. Given the nature of Tandoor Recipes, the impact is primarily data loss and corruption of personal data; however, in scenarios where Tandoor Recipes is used in a collaborative or professional environment (e.g., a restaurant managing recipes), the impact could extend to operational disruption. While the exact number of vulnerable installations is unknown, the wide adoption of Tandoor Recipes suggests a potentially large user base at risk prior to upgrading to version 2.6.4.

## Recommendation

*   Upgrade Tandoor Recipes to version 2.6.4 or later to remediate CVE-2026-35488.
*   Deploy the Sigma rule "Detect Tandoor RecipeBook Unauthorized Modification" to identify potential exploitation attempts targeting the RecipeBook API endpoint.
*   Monitor web server logs for PUT/PATCH/DELETE requests to RecipeBook API endpoints originating from users with only shared access, as indicated by anomalous HTTP request patterns related to RecipeBook IDs.
