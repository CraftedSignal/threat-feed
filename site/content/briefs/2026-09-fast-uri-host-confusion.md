---
title: Host Confusion Vulnerability in fast-uri via Malformed URI Authority
slug: 2026-09-fast-uri-host-confusion
description: The fast-uri library incorrectly parses URI authorities containing unbalanced brackets, allowing attackers to bypass SSRF denylists and security filters by causing a discrepancy between the parsed host and the host resolved by underlying HTTP clients.
date: "2026-09-28T22:15:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openjsf:fast-uri:2.4.5:*:*:*:*:node.js:*:*
  - cpe:2.3:a:openjsf:fast-uri:3.1.6:*:*:*:*:node.js:*:*
  - cpe:2.3:a:openjsf:fast-uri:4.1.3:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - ssrf
  - web-security
products:
  - fast-uri (< 4.1.4, < 3.1.7, < 2.4.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The library's parsing logic may identify a different host than the underlying HTTP client used to fetch the resource, enabling SSRF.
    confidence_band: high
cves:
  - id: CVE-2026-84394
    cvss: 7.5
    epss: 0.0038
references:
  - https://github.com/advisories/GHSA-58mr-gqgx-xq4g
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84394
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade fast-uri to 4.1.4, 3.1.7, or 2.4.6
      owner: IT Operations
      due: 48h
      evidence: This vulnerability has been patched in fast-uri 4.1.4, 3.1.7, and 2.4.6.
  mitigation_plan:
    - priority: immediate
      action: Reject URLs where host contains brackets that do not match IPv6 literal format
      owner: Application Security
      addresses: CVE-2026-84394
      evidence: If upgrading is not immediately possible, reject any URL whose host contains a [ or ] that is not a well-formed IPv6 literal before making a host decision.
---

The fast-uri library (versions < 2.4.6, < 3.1.7, and < 4.1.4) contains a host confusion vulnerability identified as CVE-2026-84394. The library fails to properly validate the authority section of a URI when it contains unbalanced or misplaced brackets (e.g., `[` or `]`). Specifically, if a host string starts with `[` but does not contain a valid IPv6 literal, `fast-uri` treats it as a standard host string without triggering an error.

This behavior is dangerous for applications using `fast-uri` to parse URLs for security decisions, such as SSRF denylists, redirect allowlists, or proxy routing. Because the library incorrectly identifies the host, a security policy may be evaluated against a malformed string while the final network request, performed by downstream libraries like `axios`, `got`, or Node.js's `http.get`, resolves the URI differently. This allows an attacker to route requests to restricted internal IP addresses or domains that the application intended to block.

## Impact

Successful exploitation allows for the bypass of security controls relying on `fast-uri` for URL validation. This can lead to Server-Side Request Forgery (SSRF) in applications that perform outgoing HTTP requests based on user-supplied URLs. Any web application or proxy service using these versions of `fast-uri` to make security decisions regarding URL reachability or internal resource access is at risk.

## Recommendation

Prioritized, concrete actions for security teams:

- Upgrade `fast-uri` to versions 4.1.4, 3.1.7, or 2.4.6 immediately to implement strict validation of URI host brackets.
- If upgrading is not possible, implement a secondary validation layer in your application that rejects any URL where the host contains `[` or `]` characters unless the entire host string matches the formal definition of an IPv6 literal (i.e., enclosed in brackets and containing valid IPv6 syntax).
- Review application logic that uses `fast-uri.parse().host` to make authorization or routing decisions to ensure the parsed host matches the intended destination.
- Audit logs for instances where external URL parameters include unexpected bracket characters, which may indicate exploitation attempts.
