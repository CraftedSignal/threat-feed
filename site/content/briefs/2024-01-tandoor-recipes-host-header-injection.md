---
title: Tandoor Recipes Host Header Injection Vulnerability (CVE-2026-33149)
slug: 2024-01-tandoor-recipes-host-header-injection
description: Tandoor Recipes versions up to 2.5.3 use a wildcard for ALLOWED_HOSTS, making Django accept any HTTP Host header without validation, which allows an attacker to manipulate server-generated absolute URLs and potentially compromise user accounts through invite link poisoning.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - host-header-injection
  - cve-2026-33149
  - web-application
vendors:
  - Tandoor Recipes
products:
  - Tandoor Recipes
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33149
rules:
  - title: Detect Anomalous Host Header
    description: Detects HTTP requests with a Host header that does not match expected patterns, potentially indicating host header injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586.001
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Unusual Domains
    description: Detects web server logs showing access to domains that are not expected.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1586.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tandoor Recipes, a recipe management and meal planning application, is vulnerable to a host header injection (CVE-2026-33149) in versions up to and including 2.5.3. The vulnerability stems from the application setting `ALLOWED_HOSTS = '*'` by default, which disables Host header validation in the Django framework. This lack of validation allows attackers to craft malicious HTTP requests with arbitrary Host headers. The application uses `request.build_absolute_uri()` to generate absolute URLs in various contexts, including invite link emails, API pagination, and OpenAPI schema generation. This vulnerability allows an attacker to manipulate these generated URLs. The most significant risk is invite link poisoning, where an attacker can make invite links in emails redirect to an attacker-controlled server, potentially compromising user accounts. No patched version is available as of the source publication date.

## Attack Chain

1. An attacker identifies a Tandoor Recipes instance running a vulnerable version (<= 2.5.3).
2. The attacker crafts an HTTP request to the Tandoor Recipes instance with a malicious `Host` header (e.g., `Host: attacker.com`).
3. An administrator of the Tandoor Recipes instance generates an invitation link for a new user.
4. The application uses `request.build_absolute_uri()` to construct the invitation link, incorporating the attacker-controlled `Host` header.
5. The invitation email is sent to the intended user, containing the malicious invitation link pointing to `attacker.com`.
6. The user clicks the malicious link in the email, unknowingly sending the invite token to the attacker's server.
7. The attacker uses the stolen invite token to create an account on the legitimate Tandoor Recipes instance.
8. The attacker gains unauthorized access to the Tandoor Recipes instance, potentially escalating privileges depending on the application's configuration and the compromised user's role.

## Impact

Successful exploitation of this vulnerability can lead to invite link poisoning, allowing attackers to create unauthorized accounts on the Tandoor Recipes instance. The number of potential victims is directly proportional to the number of Tandoor Recipes instances deployed with the vulnerable configuration and the number of users invited through the application. The impact includes unauthorized access to user data, potential modification or deletion of recipes, and the possibility of further lateral movement within the affected environment if the compromised account has elevated privileges. The CVSS v3.1 base score for this vulnerability is 8.1, indicating a high severity.

## Recommendation

*   Monitor web server logs for suspicious HTTP requests with unusual or unexpected `Host` headers to detect potential exploitation attempts. Analyze webserver logs for abnormalities in `cs-uri-query` for invite URLs (related to invite link poisoning).
*   Implement a web application firewall (WAF) rule to validate the `Host` header against a whitelist of expected values.
*   Apply available patches as soon as they are released for Tandoor Recipes to remediate CVE-2026-33149.
