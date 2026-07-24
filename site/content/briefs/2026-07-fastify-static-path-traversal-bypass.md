---
title: Fastify/static Vulnerable to Route Guard Bypass via Path Traversal
slug: 2026-07-fastify-static-path-traversal-bypass
description: The @fastify/static package is vulnerable to a route guard bypass via path traversal using non-leading '..' or '%2E%2E' path segments, allowing attackers to circumvent route-based middleware and access protected files that are served by the static plugin.
date: "2026-07-24T16:52:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - fastify
  - nodejs
  - web-vulnerability
  - path-traversal
  - webserver
vendors:
  - Fastify
products:
  - '@fastify/static'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The @fastify/static package is vulnerable to a bypass of route-based middleware and guards via non-leading `..` and `%2E%2E` path segments.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Applications that rely on route-based middleware or guards to protect files served by `@fastify/static` can be bypassed with non-leading dot-dot path segments.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Applications that rely on route-based middleware or guards to protect files served by `@fastify/static` can be bypassed... accessing protected files.
    confidence_band: high
cves:
  - id: CVE-2026-15074
    cvss: 7.5
    epss: 0.00686
references:
  - https://github.com/advisories/GHSA-83w8-p2f5-377r
rules:
  - title: Detects CVE-2026-15074 Exploitation - Fastify/static Path Traversal Bypass
    description: Detects CVE-2026-15074 exploitation - attempts to bypass fastify/static route guards using non-leading path traversal sequences in HTTP requests, such as '../' or '%2E%2E/'.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - discovery
      - initial_access
    techniques:
      - T1083
      - T1190
      - T1562
    data_sources:
      - webserver
rules_count: 1
---

The `@fastify/static` package, specifically versions up to 10.1.0, is susceptible to a route guard bypass vulnerability, tracked as CVE-2026-15074. This vulnerability enables attackers to bypass route-based middleware and access protected files served by the static plugin. The core issue lies in how the `find-my-way` router processes path segments, failing to normalize `..` or `%2E%2E` before matching routes. A previous fix for `GHSA-x428-ghpx-8j92` only addressed `%2F` variants, leaving these other path traversal sequences unhandled. Consequently, these sequences survive `decodeURI` and `encodeURI` operations, only to be collapsed later by `@fastify/send`'s `path.normalize` function, thereby circumventing initial security guards. This allows unauthorized access to sensitive files or directories intended to be protected by application-level routing.

## Attack Chain

1. An attacker crafts an HTTP GET request targeting a `fastify/static` endpoint that serves files. The request path includes a crafted sequence like `/foo/../deep/secret.txt` or `/foo/%2E%2E/deep/secret.txt`.
2. The request reaches the `find-my-way` router which is used by Fastify. Due to its inability to normalize `..` or `%2E%2E` segments before route matching, the crafted path bypasses specific, guarded routes (e.g., `/deep/*`).
3. The request instead matches the static plugin's broader catch-all route, allowing the request to proceed despite the intended route guard.
4. The `getPathnameForSend` helper, intended to prevent path traversal, processes the URI. However, it only adequately guards against `%2F` variants, allowing `..` and `%2E%2E` segments to remain in the path after `decodeURI` and `encodeURI` round-trips.
5. The request is then passed to `@fastify/send`, which internally uses `path.normalize`. This function collapses the `..` or `%2E%2E` segments, effectively resolving the path to `deep/secret.txt`.
6. The `fastify/static` plugin, now operating under the collapsed and normalized path, serves the `secret.txt` file from the `/deep/` directory, which was intended to be protected by route-based middleware.
7. The attacker successfully gains unauthorized access to the protected `secret.txt` file, circumventing the application's security controls.

## Impact

The successful exploitation of CVE-2026-15074 leads to unauthorized access to files or directories that are otherwise protected by an application's route-based middleware or guards. This can result in sensitive information disclosure, including configuration files, source code, or proprietary data, which could further enable attackers to escalate privileges, gain persistence, or exfiltrate critical business assets. Any application relying on `@fastify/static` for serving static content with route-based access controls is at risk, potentially exposing a wide range of assets.

## Recommendation

* Upgrade `@fastify/static` to version 10.1.1 or higher immediately to patch CVE-2026-15074.
* If immediate upgrade is not feasible, implement the workaround: avoid relying on route-based middleware or guards to protect files served by `@fastify/static`.
* Deploy the Sigma rule provided in this brief to your SIEM to detect attempts at exploiting this path traversal vulnerability.
