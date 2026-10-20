---
brief_id: brief-2026-10-20-follow-redirects-bypass
event_id: brief-2026-10-20-follow-redirects-bypass
revision: 1
activity_at: "2026-10-20T23:56:00Z"
title: 'follow-redirects: Array-form header credential stripping bypass'
slug: 2026-10-follow-redirects-bypass
description: The follow-redirects library fails to strip sensitive headers when provided in array format, leading to the unauthorized disclosure of credentials during cross-origin or protocol-downgrade redirects.
date: "2026-10-20T23:56:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:a:follow-redirects_project:follow-redirects:*:*:*:*:*:node.js:*:*
tags:
  - credential-access
  - nodejs
  - web-application
products:
  - follow-redirects (<= 1.16.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: 'This is an unauthenticated confidentiality vulnerability: any remote server the victim application contacts can harvest the victim''s credential headers by responding with a cross-origin redirect.'
    confidence_band: high
cves:
  - id: CVE-2026-40895
    cvss: 7.5
    epss: 0.0082
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-q3jh-wrc6-jgq8
  - https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-r4q5-vmmm-2653
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Application Security
  immediate_actions:
    - action: Audit codebase for use of follow-redirects with array-form headers in request configuration
      owner: Application Security
      due: 48h
      evidence: Source details document array-form headers as the root cause of the bypass.
  hunt_leads:
    - lead: Search for outgoing HTTP requests utilizing follow-redirects where 'headers' property is passed as an array.
      technique_id: T1530
      data_needed:
        - Codebase search/static analysis
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggerable specifically when headers are provided as an array.
  mitigation_plan:
    - priority: immediate
      action: Enforce object-based header definitions in all outgoing requests utilizing follow-redirects
      owner: Application Security
      addresses: follow-redirects credential stripping bypass
      evidence: Source PoC demonstrates that object-form headers are stripped correctly while array-form headers bypass security controls.
---

The `follow-redirects` library, a popular drop-in replacement for Node.js's native `http`/`https` modules, contains a vulnerability where sensitive header-stripping mechanisms fail when headers are provided as an array rather than a plain object. The internal `removeMatchingHeaders` function utilizes a `for...in` loop to iterate over the headers container. While this correctly matches keys in an object, it iterates over numeric indices when applied to an array, causing the header-matching regular expressions to consistently fail.

This flaw affects the security controls intended to protect credentials (Authorization, Cookie, Proxy-Authorization) and user-declared `sensitiveHeaders` (introduced in CVE-2026-40895) when a request is redirected to a different origin or a less secure protocol. Because the library silently fails to sanitize these headers, the credentials are forwarded verbatim to the attacker-controlled redirect destination. This vulnerability enables unauthenticated credential harvesting and persists in all versions of the library up to and including 1.16.0.

## Attack Chain

1. The victim application is configured to use `follow-redirects` for outgoing HTTP/HTTPS requests.
2. The application initiates a request to a malicious or compromised server, providing credentials via array-form headers (e.g., `["Authorization", "Bearer token", "Cookie", "session=id"]`).
3. The malicious server responds with a 302 or similar redirect status code pointing to an attacker-controlled cross-origin host or a protocol-downgrade (HTTPS to HTTP) endpoint.
4. `follow-redirects` intercepts the redirect and invokes `removeMatchingHeaders` to strip sensitive credentials and the original `Host` header.
5. The `removeMatchingHeaders` function iterates over the array-form headers using `for...in`, yielding numeric indices instead of header names, which results in zero matches.
6. The sanitization logic fails silently; the library retains the original credential headers and the stale `Host` header in the options object.
7. The library follows the redirect, sending the request to the attacker's server with the victim's credentials included in the headers.
8. The attacker logs the incoming request headers to harvest the victim's tokens, session cookies, or API keys.

## Impact

The vulnerability results in the unauthorized disclosure of sensitive authentication material to third-party servers. Any application utilizing `follow-redirects` that processes user-controllable or untrusted redirects is susceptible to credential harvesting. This impacts the confidentiality of session identifiers, API keys, and authorization tokens across any sector relying on the library for automated HTTP request handling.

## Recommendation

1. Update to a version of `follow-redirects` that implements explicit validation for array-form headers, ensuring either proper sanitization or a clear `TypeError` if array-form input is detected.
2. Audit applications using `follow-redirects` to determine if outgoing requests are constructed using array-form headers (e.g., `["Name", "Value"]`).
3. Implement strict cross-origin checks or proxying for sensitive traffic if an immediate patch is not feasible.
4. Ensure all developers explicitly use object-form headers (`{ "Authorization": "value" }`) until the library explicitly validates array-form header structures.
