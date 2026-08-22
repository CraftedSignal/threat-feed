---
title: TLS Hostname Verification Bypass in Netty
slug: 2026-08-netty-tls-hostname-verification
description: Netty's netty-handler library fails to perform TLS hostname verification when using the OpenSSL provider on Java 25+ systems, enabling potential man-in-the-middle attacks.
date: "2026-08-22T17:32:02Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - netty-handler (4.2.0.Final - 4.2.16.Final)
  - netty-handler (<= 4.1.136.Final)
cves:
  - id: CVE-2026-62243
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62243
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all Java applications utilizing the netty-handler library to identify versions matching the CVE-2026-62243 impact range.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-62243
  mitigation_plan:
    - priority: immediate
      action: Upgrade netty-handler to 4.2.17.Final or 4.1.137.Final
      owner: IT Operations
      addresses: CVE-2026-62243
      evidence: NVD vulnerability details
---

CVE-2026-62243 affects Netty's netty-handler library, specifically versions 4.2.0.Final through 4.2.16.Final and 4.1.136.Final and earlier. The vulnerability exists within the SslProvider.OPENSSL client path. When these specific versions are deployed in environments utilizing Java 25 or later, or in environments where Unsafe-based trust-manager wrapping is unavailable, the client fails to perform TLS hostname verification.

This flaw results in the client accepting certificates issued for arbitrary hostnames, provided a plain X509TrustManager is in use. A man-in-the-middle attacker can exploit this misconfiguration to intercept encrypted traffic, bypassing the identity validation layer of the TLS handshake. Defenders should prioritize updating to Netty versions 4.2.17.Final or 4.1.137.Final to remediate the vulnerability. Given the library's widespread use in Java-based applications, it is critical to identify all services incorporating these versions of netty-handler.

## Impact

Successful exploitation allows a man-in-the-middle attacker to decrypt, observe, and potentially modify sensitive data in transit between a client and a server. This impact is significant for applications handling authentication credentials, API keys, or personal identifiable information. As this vulnerability affects the core network communication layer, any Java application relying on the affected Netty versions as a TLS client is susceptible to traffic interception if the network path can be influenced by an attacker.

## Recommendation

* Upgrade all instances of netty-handler to 4.2.17.Final or 4.1.137.Final to resolve CVE-2026-62243.
* Audit application dependencies to identify versions of io.netty:netty-handler within the vulnerable ranges (4.2.0.Final-4.2.16.Final or <= 4.1.136.Final).
* Until patching is completed, restrict network access for affected applications to trusted environments to mitigate the risk of man-in-the-middle positioning.
