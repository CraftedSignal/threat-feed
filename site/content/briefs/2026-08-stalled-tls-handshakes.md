---
title: Service Exhaustion via Stalled TLS ALPN Handshakes
slug: 2026-08-stalled-tls-handshakes
description: Attackers are exploiting unpatched TLS listeners by flooding them with incomplete ACME ALPN handshakes to exhaust server-side resources like goroutines and worker threads.
date: "2026-08-05T21:11:55Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*
vendors:
  - Traefik Labs
  - nginx
  - HAProxy
  - Caddy
products:
  - Traefik
  - nginx
  - HAProxy
  - Caddy
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This rule detects two ALPN-based denial-of-service patterns against TLS servers.
    confidence_band: high
cves:
  - id: CVE-2026-22045
    cvss: 5.9
    epss: 0.00321
  - id: CVE-2024-5535
    cvss: 9.1
    epss: 0.05582
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22045
  - https://nvd.nist.gov/vuln/detail/CVE-2024-5535
  - https://www.rfc-editor.org/rfc/rfc8737
  - https://www.elastic.co/guide/en/beats/packetbeat/current/configuration-tls.html
---

This threat involves the abuse of the acme-tls/1 ALPN extension to trigger denial-of-service conditions against TLS-enabled reverse proxies. Attackers initiate high volumes of TLS connections advertising the acme-tls/1 extension, a protocol intended only for ACME TLS-ALPN-01 certificate validation, and deliberately stall the handshake process. By failing to complete the handshake, the attacker forces the destination service to maintain open connection states, effectively exhausting available goroutines, worker threads, or accept queue depths. This exploitation pattern is specifically documented as a technique to target CVE-2026-22045, which affects services like Traefik that lack adequate handshake timeout enforcement. When performed at scale, this resource exhaustion results in a denial-of-service (DoS) for legitimate users. Defenders should monitor for repeated incomplete TLS sessions originating from non-authorized sources to identify exploitation attempts against edge infrastructure.

## Impact

Successful exploitation leads to a denial of service on internet-facing reverse proxies and web application load balancers, impacting service availability. Affected infrastructure includes common reverse proxies such as Traefik, nginx, HAProxy, and Caddy. If handshake timeouts are not correctly configured, a relatively low-volume flood can exhaust server resources, causing service instability or total outage for the host.

## Recommendation

Prioritize hardening of all internet-facing TLS listeners to prevent resource exhaustion.
- Upgrade Traefik and other reverse proxies to versions that explicitly address CVE-2026-22045 and related handshake-timeout vulnerabilities.
- Enforce strict `ssl_handshake_timeout` settings at the listener level to bound the duration any connection can remain in a pending state.
- Rate-limit inbound TLS connections per source IP at the network perimeter to mitigate the impact of connection-flooding attacks.
- Configure the Elastic Agent `network_traffic` integration with `include_detailed_fields: true` to ensure visibility into ALPN extension fields.
- Suppress noise by creating allowlists for known ACME Certificate Authority IP ranges (e.g., Let's Encrypt, ZeroSSL, Buypass) and internal certificate renewal agents.
