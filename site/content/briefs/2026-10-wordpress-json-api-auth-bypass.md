---
title: Authentication Bypass in WordPress JSON API Auth Plugin (CVE-2026-97637)
slug: 2026-10-wordpress-json-api-auth-bypass
description: An authentication bypass vulnerability in the WordPress JSON API Auth plugin allows unauthenticated attackers to hijack administrative sessions via cached HTTP responses.
date: "2026-10-02T08:22:54Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:wordpress:json_api_auth:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - web-application
  - authentication-bypass
  - cve
vendors:
  - WordPress
products:
  - JSON API Auth (<= 3.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The JSON API Auth plugin for WordPress is vulnerable to Authentication Bypass via Cached Session Cookie Disclosure.
    confidence_band: high
cves:
  - id: CVE-2026-97637
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97637
rules:
  - title: Detect CVE-2026-97637 Exploitation Attempts - Insecure Auth Bypass Parameter
    description: Detects exploitation attempts against the WordPress JSON API Auth plugin where attackers append 'insecure=cool' to bypass security checks.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rule to block requests containing 'insecure=cool'
      owner: SOC
      due: 4h
      evidence: Source documentation identifies this parameter as a bypass mechanism
    - action: Upgrade JSON API Auth plugin to fixed version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-97637 vulnerability resolution
  hunt_leads:
    - lead: Search logs for successful 200 OK responses to /api/auth/generate_auth_cookie/ requests originating from unauthorized IPs
      technique_id: T1190
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The endpoint returns live session cookies in the JSON response body
  mitigation_plan:
    - priority: immediate
      action: Disable JSON API Auth plugin until patch application
      owner: IT Operations
      addresses: CVE-2026-97637
      evidence: Plugin architecture allows bypass of authentication controls
---

CVE-2026-97637 describes an authentication bypass vulnerability affecting versions of the JSON API Auth plugin for WordPress up to and including 3.1.2. The vulnerability originates in the PI-Media/json-api parent plugin, which improperly caches controller dispatch results based solely on URI and query strings. Crucially, this caching mechanism fails to distinguish between HTTP methods or evaluate the contents of POST bodies.

The plugin's `generate_auth_cookie()` endpoint, which returns a valid WordPress `logged_in` session cookie within the JSON response body, becomes susceptible to this caching flaw. When an administrator performs an authentication action via POST, the result is cached. An unauthenticated attacker can subsequently issue a GET request to the same URI to retrieve the cached response, including the valid administrator cookie. By also supplying the `insecure=cool` parameter, an attacker can bypass the plugin's HTTPS enforcement check. Successful exploitation leads to full administrative account takeover.

## Attack Chain

1. Attacker monitors traffic or waits for a target site administrator to perform a legitimate POST request to `/api/auth/generate_auth_cookie/`.
2. The vulnerable PI-Media/json-api plugin processes the administrator's request and stores the controller result, including the sensitive `logged_in` session cookie, in the server cache.
3. Attacker identifies the specific URI and query parameters associated with the administrator's recent authentication event.
4. Attacker constructs a malicious GET request targeting the same URI, appending the `insecure=cool` parameter to bypass HTTPS validation logic.
5. The server identifies a cache hit for the URI and returns the stored JSON response, effectively leaking the administrator's session cookie to the attacker.
6. Attacker extracts the `logged_in` session cookie from the received JSON response.
7. Attacker uses the stolen session cookie to authenticate to the WordPress site as an administrator.
8. Attacker gains full administrative access to the site, allowing for configuration changes, malicious plugin installation, or data exfiltration.

## Impact

Successful exploitation results in full administrative account takeover of the affected WordPress site. Given the plugin's role, this provides attackers with persistent access, the ability to execute arbitrary administrative tasks, install malicious code, or exfiltrate sensitive site data. Organizations using the JSON API Auth plugin are at risk of complete site compromise.

## Recommendation

Prioritize updating the JSON API Auth plugin to a version addressing CVE-2026-97637. If an update is unavailable, disable the JSON API Auth plugin immediately.

- Audit web server access logs for requests targeting `/api/auth/generate_auth_cookie/` that include the `insecure=cool` parameter, as this is a high-confidence indicator of exploitation attempts.
- Audit administrative user session activity for unauthorized logins following observed GET requests to the identified API endpoints.
- Implement a Web Application Firewall (WAF) rule to block any incoming HTTP requests containing the `insecure=cool` parameter.
