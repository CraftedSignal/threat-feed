---
title: IP Spoofing Vulnerability in go-chi/chi middleware.RealIP
slug: 2026-09-chi-middleware-spoofing
description: The go-chi/chi middleware.RealIP component contains a vulnerability (CVE-2026-72815) that allows attackers to bypass IP-based ACLs and rate limits by forging the X-Forwarded-For header.
date: "2026-09-10T02:08:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:go-chi:chi:*:*:*:*:*:*:*:*
vendors:
  - Go-Chi
products:
  - chi (>= 5.2.1, < 5.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The vulnerable middleware allows bypassing IP-based ACLs via attacker-controlled X-Forwarded-For headers.
    confidence_band: high
cves:
  - id: CVE-2026-72815
    epss: 0.00397
references:
  - https://github.com/go-chi/chi/security/advisories/GHSA-3fxj-6jh8-hvhx
  - https://sploitus.com/exploit?id=96BA85C0-9261-5C52-BC77-CE0531979D65&utm_source=rss&utm_medium=rss
  - https://github.com/go-chi/chi/pull/967
action_plan:
  priority: elevated
  owners:
    - Engineering
    - Security Operations
  immediate_actions:
    - action: Upgrade go-chi/chi to v5.3.0 or later across all projects
      owner: Engineering
      due: 48h
      evidence: Fixed version 5.3.0 specified in advisory
  mitigation_plan:
    - priority: immediate
      action: Migrate from RealIP to ClientIPFrom* middleware in application code
      owner: Engineering
      addresses: CVE-2026-72815
      evidence: Advisory recommends replacing RealIP with secure alternatives
---

The go-chi/chi Go library, specifically the `middleware.RealIP` component, is vulnerable to an IP spoofing flaw tracked as CVE-2026-72815. The middleware insecurely parses the `X-Forwarded-For` HTTP header, trusting the leftmost value provided by the client to populate `http.Request.RemoteAddr`. Because the `X-Forwarded-For` header is user-controllable, an attacker can supply a forged header (e.g., `X-Forwarded-For: 127.0.0.1`) to trick the application into believing the request originates from a trusted source, such as the local loopback or a privileged IP range. 

This flaw effectively facilitates the bypass of security controls that rely exclusively on IP-based authentication, authorization, or rate limiting. The issue affects go-chi/chi versions 5.2.1 up to, but not including, 5.3.0. While version 5.3.0 introduces secure alternatives, the vulnerable `middleware.RealIP` remains for backward compatibility, requiring manual code changes by developers to switch to the new `ClientIPFrom*` middleware series.

## Impact

Successful exploitation allows unauthenticated attackers to bypass IP-based ACLs and rate-limiting policies. This can lead to unauthorized access to administrative endpoints or services restricted to specific IP addresses. Given the ubiquity of go-chi in Go-based web applications, the impact on security services relying on source IP identification is significant.

## Recommendation

Prioritized actions for development and security engineering teams:

- Update `go-chi/chi` to version 5.3.0 or later immediately.
- Audit existing middleware implementations to replace `middleware.RealIP` with the appropriate `ClientIPFrom*` variants (e.g., `ClientIPFromXFF`) that account for trusted proxy chains.
- Implement infrastructure-level security to ensure that reverse proxies (e.g., Nginx, Envoy, AWS ALB) correctly strip or overwrite incoming `X-Forwarded-For` headers from untrusted clients before the request reaches the Go application.
- De-prioritize IP-based ACLs for critical authentication or authorization flows, favoring robust identity-based authentication mechanisms.
