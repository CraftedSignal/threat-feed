---
title: OAuth2 Proxy Authentication Bypass Vulnerability (CVE-2026-41059)
slug: 2024-01-09-oauth2-auth-bypass
description: OAuth2 Proxy versions 7.5.0 through 7.15.1 are vulnerable to an authentication bypass (CVE-2026-41059) due to improper handling of URL fragments in conjunction with `skip_auth_routes` or `skip_auth_regex`, potentially allowing unauthenticated access to protected resources.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth2proxy
  - authentication-bypass
  - cve
vendors:
  - OAuth2 Proxy
products:
  - OAuth2 Proxy
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41059
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41059
rules:
  - title: OAuth2 Proxy Authentication Bypass Attempt via URL Fragment
    description: 'Detects attempts to bypass OAuth2 Proxy authentication by using URL fragments (%23 or #) in the request path, exploiting CVE-2026-41059.'
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1190
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: OAuth2 Proxy Authentication Bypass - Skip Auth Route Exploitation
    description: Detects potential exploitation of OAuth2 Proxy skip_auth_routes by looking for requests matching wide patterns that may be vulnerable to the CVE-2026-41059
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1190
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OAuth2 Proxy, a reverse proxy providing authentication using OAuth2 providers, is susceptible to an authentication bypass vulnerability (CVE-2026-41059) affecting versions 7.5.0 through 7.15.1. This vulnerability arises when specific configurations are in place: the use of `skip_auth_routes` or the legacy `skip_auth_regex` with patterns vulnerable to attacker-controlled suffix widening (e.g., `^/foo/.*/bar$`), and protected upstream applications that interpret `#` as a fragment delimiter.  An attacker can exploit this by crafting requests containing a number sign (`#` or its encoded form `%23`) to match public allowlist rules, while the backend inadvertently serves protected resources.  Organizations using OAuth2 Proxy within this vulnerable range should upgrade to version 7.15.2 or implement mitigations.

## Attack Chain

1.  An attacker identifies an OAuth2 Proxy instance running a vulnerable version (7.5.0 - 7.15.1) and configuration, specifically utilizing `skip_auth_routes` or `skip_auth_regex` with overly permissive patterns.
2.  The attacker crafts a malicious HTTP request targeting a protected resource, embedding a `#` or `%23` within the URI path. For example, a request to `/foo/secret%23bar`.
3.  OAuth2 Proxy evaluates the request against the configured `skip_auth_routes` or `skip_auth_regex` rules.  The crafted path bypasses the authentication check because the initial segment matches the allowed pattern (e.g., `/foo/`).
4.  OAuth2 Proxy forwards the request to the upstream application without authentication.
5.  The upstream application receives the request. Due to the presence of `#` or `%23`, the application might interpret the URL differently, possibly ignoring the fragment and routing the request to the protected resource (e.g., `/foo/secret`).
6.  The upstream application, believing the request is legitimate, processes the request and potentially returns sensitive data.
7.  The attacker receives the unauthorized response from the upstream application, successfully bypassing authentication.

## Impact

Successful exploitation of CVE-2026-41059 allows unauthenticated attackers to access protected resources and sensitive data behind OAuth2 Proxy. The impact is highly dependent on the nature of the protected resources, potentially leading to data breaches, unauthorized access to administrative interfaces, and other security compromises. The number of affected organizations is unknown but depends on the prevalence of vulnerable OAuth2 Proxy configurations.

## Recommendation

*   Upgrade OAuth2 Proxy to version 7.15.2 or later to patch CVE-2026-41059.
*   Tighten or remove `skip_auth_routes` and `skip_auth_regex` rules, especially patterns that use broad wildcards across path segments, as mentioned in the advisory for CVE-2026-41059.
*   Implement ingress, load balancer, or WAF rules to reject requests whose path contains `%23` or `#`, as recommended in the CVE-2026-41059 advisory.
*   Deploy the Sigma rule "OAuth2 Proxy Authentication Bypass Attempt via URL Fragment" to detect exploitation attempts.
