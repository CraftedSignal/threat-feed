---
brief_id: brief-2026-10-30-sniproxy-null-pointer
event_id: brief-2026-10-30-sniproxy-null-pointer
revision: 1
activity_at: "2026-10-30T23:46:22Z"
title: 'sniproxy: NULL pointer dereference in resolv_cancel (CVE-2026-119760)'
slug: 2026-10-sniproxy-null-pointer
description: sniproxy through 0.7.0 contains a NULL pointer dereference vulnerability in resolv_cancel() that allows remote unauthenticated attackers to crash the daemon by sending overlong hostnames.
date: "2026-10-30T23:46:22Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:sniproxy:sniproxy:*:*:*:*:*:*:*:*
vendors:
  - sniproxy
products:
  - sniproxy (through 0.7.0)
cves:
  - id: CVE-2026-119760
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119760
---

sniproxy through 0.7.0 contains a NULL pointer dereference vulnerability in `resolv_cancel()` that allows remote unauthenticated attackers to crash the daemon. Attackers can send a 254 or 255 character TLS SNI name or HTTP Host header matching a wildcard backend, then close the connection to terminate the proxy.
