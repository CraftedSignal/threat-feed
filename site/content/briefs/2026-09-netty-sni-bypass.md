---
title: Netty SNI Routing and mTLS Bypass Vulnerability
slug: 2026-09-netty-sni-bypass
description: A vulnerability in the Netty TLS ClientHello parsing logic allows unauthenticated attackers to bypass SNI-based mTLS requirements by sending fragmented handshake data that triggers a fallback to a permissive default SSL context.
date: "2026-09-08T20:04:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
vendors:
  - Netty
products:
  - 'netty-handler (vulnerable: >= 4.2.0.Final, <= 4.2.16.Final)'
  - 'netty-handler (vulnerable: <= 4.1.136.Final)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A fragmented TLS ClientHello whose handshake header spans multiple records makes Netty silently fall back to the default SslContext; where per-SNI selection is the sole mTLS gate, an unauthenticated attacker can bypass the route's mTLS requirement.
    confidence_band: high
cves:
  - id: CVE-2026-75595
    epss: 0.00317
references:
  - https://github.com/advisories/GHSA-c4c3-7fpv-j4q5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75595
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade netty-handler to 4.1.137.Fina or later
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory GHSA-c4c3-7fpv-j4q5
  mitigation_plan:
    - priority: immediate
      action: Review SSLContext configuration for permissive client authentication defaults
      owner: Application Security
      addresses: CVE-2026-75595
      evidence: Advisory states fallback to default context is the mechanism for bypass
---

The Netty framework contains a vulnerability (CVE-2026-75595) in `io.netty.handler.ssl.SslClientHelloHandler` where the parser incorrectly validates the TLS ClientHello handshake header. Specifically, the implementation fails to account for the 5-byte TLS record header when calculating the offset for the handshake length. If a client sends a fragmented TLS ClientHello such that the first record's payload is less than 4 bytes, the parser encounters an IndexOutOfBoundsException. This exception is caught by a generic handler that silently falls back to the default `SslContext`.

This flaw becomes a critical security risk when mTLS is enforced exclusively through per-SNI `SslContext` selection. If an organization relies on SNI-based routing to apply mTLS requirements (clientAuth=REQUIRE) but maintains a permissive default `SslContext` (clientAuth=NONE or OPTIONAL) for fallback, an unauthenticated attacker can bypass the intended mTLS protection by intentionally fragmenting the initial TLS handshake to trigger the fallback logic.

## Impact

Successful exploitation allows an unauthenticated attacker to bypass mTLS authentication controls on affected systems. This impacts any environment relying on per-SNI `SslContext` selection as the primary mechanism for mTLS enforcement without secondary application-layer peer-certificate validation. Depending on the backend application, this could lead to unauthorized access to internal services or API endpoints that expect authenticated client traffic.

## Recommendation

Prioritize the upgrade of all applications using the `netty-handler` library to patched versions. As this is a library-level vulnerability, detection engineering should focus on application-layer logging and monitoring of TLS connection configurations.

* Upgrade `io.netty:netty-handler` to version 4.1.137.Final or 4.2.17.Final or later, as provided by the vendor.
* Review server-side TLS configurations to ensure that the default `SslContext` is not configured with permissive client authentication (clientAuth=NONE) if the application handles sensitive routes.
* Implement application-layer peer-certificate validation to ensure that mTLS requirements are enforced regardless of the initial TLS routing context.
