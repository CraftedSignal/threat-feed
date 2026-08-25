---
title: OAuth Redirect URI Validation Bypass in Ech0
slug: 2026-08-ech0-oauth-bypass
description: Ech0 versions 4.5.6 and earlier contain an OAuth redirect URI validation flaw that permits attackers to intercept authorization codes, enabling full account compromise.
date: "2026-08-25T14:08:30Z"
lastmod: "2026-08-25T16:16:49Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-79662&utm_source=rss&utm_medium=rss
vendors:
  - Ech0
products:
  - Ech0 (<= 4.5.6)
  - Ech0 (4.3.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ech0 version 4.3.4 and earlier fails to reliably enforce scoped access token (least-privilege) restrictions on several privileged admin routes.
    confidence_band: high
cves:
  - id: CVE-2026-79662
    cvss: 8
  - id: CVE-2026-79667
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79662
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79667
  - https://sploitus.com/exploit?id=CVE-2026-79662&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Ech0 instances to version 4.7.3
      owner: IT Operations
      due: 24h
      evidence: Fixed in 4.7.3
  mitigation_plan:
    - priority: immediate
      action: Monitor logs for /api/auth/exchange requests
      owner: Security Operations
      addresses: CVE-2026-79662
      evidence: Attacker can trade exchange code for victim access tokens at the public POST /api/auth/exchange endpoint
updates:
  - at: "2026-08-25T14:08:47Z"
    level: L2
    summary: added coverage for Ech0 (4.3.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-79667
  - at: "2026-08-25T16:16:49Z"
    level: L2
    summary: poc_available; added CVE-2026-79667
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-79662&utm_source=rss&utm_medium=rss
---

Ech0 versions up to 4.5.6 contain a critical OAuth redirect URI validation vulnerability located in the parseAndValidateClientRedirect function within internal/service/auth/auth.go. The vulnerability arises because the application only performs allowlist validation on the scheme and host components of a user-supplied redirect_uri, failing to account for path, query, and fragment parameters. 

This logic error allows an attacker to craft a redirect_uri that points to a legitimate, allowlisted domain while embedding malicious paths or query strings. When a victim initiates an authentication flow, the application embeds this attacker-controlled URI into the signed state JWT. Following the OAuth exchange, the victim is redirected to the attacker-influenced URI, inadvertently leaking the one-time authorization code. If this code is captured through mechanisms such as Referer headers, analytics logs, or secondary open redirects, the attacker can leverage the /api/auth/exchange endpoint to gain unauthorized access to the victim's account. This flaw is resolved in version 4.7.3.

## Impact

Successful exploitation of this vulnerability results in full account takeover for affected users. By intercepting a valid one-time authorization code, an attacker can exchange it for legitimate access and refresh tokens, effectively bypassing authentication. This risk extends to all users of the affected Ech0 instances, including administrative accounts if they perform authentication in environments where URI leakage is possible.

## Recommendation

* Upgrade all Ech0 instances to version 4.7.3 or later to patch the redirect validation logic in the authentication service.
* Audit web server and application logs for suspicious requests to /api/auth/exchange that deviate from normal client-side authentication patterns, such as multiple exchanges originating from anomalous user-agents or unexpected network segments.
* Implement stricter URI validation policies in all OAuth-enabled services, ensuring that entire URI structures (not just scheme and host) are validated against defined allowlists.
