---
title: ORY Oathkeeper Authentication Bypass Vulnerability (CVE-2026-33496)
slug: 2024-01-ory-oathkeeper-auth-bypass
description: ORY Oathkeeper before 26.2.0 is vulnerable to authentication bypass (CVE-2026-33496) due to cache key confusion in the `oauth2_introspection` authenticator, allowing attackers with a valid token to bypass authentication by reusing it with different introspection URLs.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - vulnerability
  - oathkeeper
  - cache-poisoning
  - cloud
vendors:
  - ORY
products:
  - Oathkeeper
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33496
rules:
  - title: Detect ORY Oathkeeper Authentication Bypass Attempt via HTTP Request
    description: Detects potential authentication bypass attempts against ORY Oathkeeper by monitoring HTTP requests with suspicious patterns indicative of exploiting CVE-2026-33496, focusing on access to different protected resources using the same token shortly after each other.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect ORY Oathkeeper Vulnerable Version in HTTP User-Agent
    description: Detects potentially vulnerable ORY Oathkeeper versions based on the User-Agent string observed in HTTP requests. This rule identifies requests originating from versions prior to 26.2.0.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ORY Oathkeeper, an Identity & Access Proxy, is susceptible to an authentication bypass vulnerability (CVE-2026-33496) affecting versions prior to 26.2.0. This vulnerability stems from a cache key confusion issue within the `oauth2_introspection` authenticator. The cache fails to differentiate between tokens validated using different introspection URLs. This allows an attacker, who has legitimately obtained a valid token for one of the configured introspection servers, to prime the cache and subsequently reuse the same token for access rules intended for a different introspection server. The attack requires the Oathkeeper instance to be configured with multiple `oauth2_introspection` authenticators, all utilizing caching. This poses a significant risk as it enables unauthorized access to protected resources. Version 26.2.0 addresses this issue by incorporating the introspection server URL into the cache key.

## Attack Chain

1.  The attacker identifies an ORY Oathkeeper instance running a version prior to 26.2.0 configured with multiple `oauth2_introspection` authenticators using caching.
2.  The attacker obtains a valid OAuth2 token for one of the configured introspection endpoints, potentially through legitimate means or by compromising a service that issues tokens for that endpoint.
3.  The attacker crafts a request to a protected resource that is governed by an access rule configured to use the compromised token's introspection endpoint. This primes the Oathkeeper's cache with the token's validation result.
4.  The attacker then crafts a second request to a *different* protected resource that is governed by an access rule configured to use a *different* introspection endpoint. Critically, this request uses the *same* token.
5.  Due to the cache key collision, Oathkeeper incorrectly uses the cached validation result from the first introspection endpoint for the second request.
6.  If the token is considered valid based on the cached result (even though it should be invalid for the second introspection endpoint), Oathkeeper grants unauthorized access to the protected resource.
7.  The attacker successfully bypasses authentication and gains access to a resource they should not be authorized to access.

## Impact

Successful exploitation of CVE-2026-33496 allows an attacker to bypass authentication and gain unauthorized access to protected resources managed by ORY Oathkeeper. The number of affected organizations depends on the adoption rate of ORY Oathkeeper and the number of instances running vulnerable versions with the specific misconfiguration (multiple `oauth2_introspection` authenticators with caching enabled). If exploited, this vulnerability can lead to data breaches, unauthorized modification of resources, and other security incidents.

## Recommendation

*   Upgrade ORY Oathkeeper to version 26.2.0 or later to incorporate the fix for CVE-2026-33496.
*   As a temporary workaround, disable caching for `oauth2_introspection` authenticators to mitigate the vulnerability until an upgrade can be performed, as suggested in the advisory.
