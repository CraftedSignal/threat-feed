---
title: Hostname Verification Bypass in Netty QUIC Certificate Validation
slug: 2026-09-netty-quic-mitm
description: Netty versions 4.2.11.Final through 4.2.17.Final contain an incomplete hostname verification fix in the QUIC certificate verification path, allowing network-adjacent attackers to bypass certificate validation and conduct man-in-the-middle attacks.
date: "2026-09-26T15:09:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netty:netty:4.2.11:*:*:*:*:*:*:*
vendors:
  - Netty
products:
  - Netty (4.2.11.Final through 4.2.17.Final)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Attackers on the network path can present a certificate chain for the wrong hostname that the plain trust manager accepts, bypassing hostname authentication for QUIC clients.
    confidence_band: high
cves:
  - id: CVE-2026-100665
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100665
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade Netty to version 4.2.18.Final or later
      owner: Application Security
      addresses: CVE-2026-100665
      evidence: Netty versions from 4.2.11.Final before 4.2.18.Final contain an incomplete hostname verification fix
---

Netty versions 4.2.11.Final through 4.2.17.Final are affected by a security flaw (CVE-2026-100665) involving the QUIC certificate verification path. When developers utilize a plain X509TrustManager, the BoringSSLCertificateVerifyCallback improperly discards the SSLEngine during the TLS handshake process. This architectural error prevents the necessary endpoint identification logic from executing, even when HTTPS verification is explicitly configured by the application. Consequently, the client fails to validate that the hostname provided in the certificate matches the intended connection destination. An attacker positioned on the network path between the client and the server can present a certificate chain for an arbitrary hostname, which the client will erroneously accept as legitimate, facilitating successful man-in-the-middle (MitM) interceptions and potential exfiltration of sensitive traffic. This vulnerability affects any Netty-based application utilizing the QUIC transport with the specified trust manager configuration.

## Impact

Successful exploitation allows a network-adjacent attacker to transparently intercept, inspect, or modify encrypted communications between a client and server. This bypasses the security guarantees of TLS for affected QUIC connections, potentially exposing credentials, session tokens, or sensitive application data. The impact is significant for organizations relying on Netty for high-performance QUIC-based service-to-service communication.

## Recommendation

Prioritize the upgrade of all instances utilizing Netty 4.2.11.Final through 4.2.17.Final to Netty 4.2.18.Final or later. As this is a library-level vulnerability, there are no reliable endpoint or network-based detection signatures for the exploitation attempt itself, as the bypass occurs during the internal TLS handshake logic. Engineering teams should audit dependency trees for affected Netty versions and verify that the QUIC transport configuration does not rely on deprecated or insecure X509TrustManager implementations until patching is completed.
