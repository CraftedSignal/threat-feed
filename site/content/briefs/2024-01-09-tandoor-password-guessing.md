---
title: Tandoor Recipes Unauthenticated Password Guessing Vulnerability (CVE-2026-33152)
slug: 2024-01-09-tandoor-password-guessing
description: Tandoor Recipes before 2.6.0 allows unauthenticated attackers to perform high-speed password guessing attacks against any known username due to improper rate limiting on API endpoints using BasicAuthentication.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-33152
  - tandoor-recipes
  - password-guessing
  - credential-access
vendors:
  - Tandoor Recipes
products:
  - Tandoor Recipes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33152
rules:
  - title: Detect Tandoor Recipes Basic Authentication Brute Force
    description: Detects potential brute force attacks against Tandoor Recipes API endpoints using Basic Authentication by monitoring for multiple failed authentication attempts from the same IP address within a short time frame.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
  - title: Tandoor Recipes API Access with Basic Auth
    description: Detects successful authentication to Tandoor Recipes API using Basic Authentication. This can be used to identify legitimate API access or to investigate potential credential compromise.
    platform: sigma
    severity: informational
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tandoor Recipes, a recipe management and meal planning application, is susceptible to a critical vulnerability (CVE-2026-33152) in versions prior to 2.6.0. The application's configuration of Django REST Framework with BasicAuthentication as a default authentication backend, combined with insufficient rate limiting, creates a significant security risk. The AllAuth rate limiting (ACCOUNT_RATE_LIMITS: login: 5/m/ip) is only applied to the HTML login endpoint (/accounts/login/), leaving API endpoints unprotected. This allows attackers to bypass rate limiting and account lockout mechanisms by sending authentication requests directly to the API. This vulnerability enables an attacker to perform unlimited password attempts against valid usernames, potentially gaining unauthorized access to user accounts and sensitive data. Tandoor Recipes version 2.6.0 addresses this vulnerability.

## Attack Chain

1. The attacker identifies a Tandoor Recipes instance running a version prior to 2.6.0.
2. The attacker discovers valid usernames through OSINT techniques or by leveraging other vulnerabilities (not described in source).
3. The attacker crafts HTTP requests with `Authorization: Basic` headers targeting an API endpoint that accepts authenticated requests.
4. The attacker sends multiple requests with different password guesses using a scripting language like Python and the `requests` library.
5. The Tandoor Recipes server authenticates the request if the credentials match a valid user.
6. If successful, the attacker gains access to the targeted user's account.
7. The attacker accesses, modifies, or exfiltrates recipes, meal plans, shopping lists, and potentially other user data.
8. The attacker pivots to other user accounts if sufficient privileges exist, further expanding their access and potential damage.

## Impact

Successful exploitation of CVE-2026-33152 allows attackers to compromise user accounts on vulnerable Tandoor Recipes instances. This can lead to unauthorized access to sensitive user data, including personal recipes, meal plans, and shopping lists. Depending on the application's deployment and user permissions, attackers may also be able to modify data, add malicious content, or pivot to other systems. The lack of rate limiting makes password guessing attacks highly effective, increasing the risk of widespread account compromise.

## Recommendation

*   Upgrade Tandoor Recipes instances to version 2.6.0 or later to patch CVE-2026-33152.
*   Implement rate limiting on API endpoints that accept BasicAuthentication, independent of AllAuth's HTML login rate limiting.
*   Deploy the Sigma rule `Detect Tandoor Recipes Basic Authentication Brute Force` to identify potential password guessing attempts against Tandoor Recipes instances in your environment.
*   Monitor web server logs for excessive `Authorization: Basic` header usage targeting Tandoor Recipes API endpoints.
