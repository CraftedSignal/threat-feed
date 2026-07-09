---
title: 'CVE-2026-11404: Cesanta Mongoose TLS Out-of-Bounds Read Leading to Denial of Service'
slug: 2026-07-cesanta-mongoose-tls-oob-read-dos
description: Cesanta Mongoose before version 7.22 contains an out-of-bounds read vulnerability (CVE-2026-11404) in its built-in TLS server function, `mg_tls_server_recv_hello()`, allowing a remote, unauthenticated attacker to send a specially crafted TLS ClientHello message with an oversized session ID length, leading to a service crash and denial of service for HTTPS, MQTTS, or WSS services.
date: "2026-07-09T16:18:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - vulnerability
  - tls
  - webserver
  - firmware
vendors:
  - Cesanta
products:
  - Mongoose (before 7.22)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can send a single crafted ClientHello with an oversized session id length to read past the receive buffer, crashing any HTTPS, MQTTS, or WSS service built on MG_TLS_BUILTIN.
    confidence_band: high
cves:
  - id: CVE-2026-11404
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11404
---

The Cesanta Mongoose library, specifically versions prior to 7.22, is affected by a critical out-of-bounds read vulnerability, identified as CVE-2026-11404. This flaw resides within the `mg_tls_server_recv_hello()` function, a core component of its built-in TLS server (MG_TLS_BUILTIN). Attackers can exploit this by sending a single, specially crafted TLS ClientHello message. This malicious ClientHello contains an intentionally oversized `session_id_len` byte, which the vulnerable function uses as a buffer index without proper validation against the length of the received data. The consequence is an attempt to read memory beyond the allocated receive buffer, leading to a severe application crash. This vulnerability enables a remote, unauthenticated attacker to trigger a denial of service on any HTTPS, MQTTS, or WSS service built using the affected Mongoose library, disrupting critical services. This issue highlights the importance of input validation in network protocol implementations.

## Attack Chain

1. A remote, unauthenticated attacker initiates a TLS connection to a vulnerable Cesanta Mongoose service (e.g., HTTPS, MQTTS, WSS) that utilizes the MG_TLS_BUILTIN feature.
2. The attacker sends a specially crafted TLS ClientHello message to the server as part of the TLS handshake.
3. Within the ClientHello message, the attacker manipulates the `session_id_len` byte to contain an oversized, invalid value.
4. The vulnerable `mg_tls_server_recv_hello()` function in Mongoose processes the ClientHello without adequately validating the `session_id_len` against the actual length of the received data.
5. The function attempts to use the oversized `session_id_len` as a buffer index, resulting in an out-of-bounds read operation past the legitimate boundaries of the receive buffer.
6. This memory access violation triggers a critical error, causing the Cesanta Mongoose application to crash.
7. The application crash leads to a denial of service, rendering the affected HTTPS, MQTTS, or WSS service unavailable to legitimate users.

## Impact

The successful exploitation of CVE-2026-11404 leads to a complete denial of service for any internet-facing service utilizing the affected Cesanta Mongoose library with MG_TLS_BUILTIN enabled. Services such as HTTPS, MQTTS, and WSS will crash, becoming unavailable to legitimate users. This can result in significant operational disruption, potential data loss (if not properly handled during the crash), and reputational damage for affected organizations. While the vulnerability is not described as leading to arbitrary code execution or data exfiltration, the ability for an unauthenticated attacker to reliably crash critical services poses a high risk.

## Recommendation

* Patch CVE-2026-11404 by upgrading Cesanta Mongoose to version 7.22 or later immediately.
* Monitor affected services (HTTPS, MQTTS, WSS) for unexpected restarts or crashes, which could indicate attempted exploitation of this vulnerability.
* Implement robust service availability monitoring and alerting for any prolonged outages of applications utilizing Cesanta Mongoose with MG_TLS_BUILTIN.
