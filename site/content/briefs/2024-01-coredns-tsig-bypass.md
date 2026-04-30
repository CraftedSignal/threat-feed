---
title: CoreDNS TSIG Authentication Bypass Vulnerability
slug: 2024-01-coredns-tsig-bypass
description: CoreDNS versions prior to 1.14.3 are vulnerable to TSIG authentication bypass on gRPC, QUIC, DoH, and DoH3 transports, allowing unauthenticated network attackers to bypass authentication and potentially access TSIG-protected zone data or submit dynamic DNS updates.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - coredns
  - tsig
  - authentication-bypass
vendors:
  - coredns
products:
  - coredns
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-vp29-5652-4fw9
rules:
  - title: Detect CoreDNS AXFR Request over DoH with Forged TSIG
    description: Detects a DNS zone transfer request (AXFR) over DoH with a forged TSIG record, indicating a potential TSIG authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1588.004
    data_sources:
      - webserver
      - linux
  - title: Detect CoreDNS gRPC/QUIC Request with Invalid TSIG HMAC
    description: Detects gRPC or QUIC requests to CoreDNS where a TSIG key name is present but the HMAC is invalid, indicating a possible bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.004
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CoreDNS versions prior to 1.14.3 contain a flaw in the handling of TSIG authentication for gRPC, QUIC, DoH, and DoH3 transports. Specifically, gRPC and QUIC transports only check for the presence of a TSIG key name without verifying the HMAC, while DoH and DoH3 transports unconditionally return a successful TSIG status. This vulnerability allows unauthenticated attackers to bypass TSIG authentication, potentially enabling unauthorized zone transfers, dynamic updates, and access to other TSIG-protected resources. This issue was identified in version 1.14.2 and prior, and affects deployments where TSIG authentication is relied upon for secure DNS operations over these transports.

## Attack Chain

1. The attacker identifies a CoreDNS server using gRPC, QUIC, DoH, or DoH3 with TSIG authentication enabled.
2. For gRPC/QUIC, the attacker crafts a DNS request with a valid TSIG key name but a forged or invalid HMAC value. For DoH/DoH3, the attacker crafts a DNS request with any TSIG record.
3. The attacker sends the crafted request to the CoreDNS server via the affected transport (gRPC, QUIC, DoH, or DoH3).
4. CoreDNS receives the request and processes the TSIG information. For gRPC/QUIC, CoreDNS checks if the TSIG key name exists in the configuration. For DoH/DoH3, the transport layer reports successful TSIG verification without performing actual verification.
5. The TSIG check passes due to the vulnerability: either HMAC is not validated (gRPC/QUIC) or TSIG status is unconditionally reported as valid (DoH/DoH3).
6. The request is passed to the appropriate plugin, bypassing TSIG authentication requirements.
7. The attacker gains access to TSIG-protected functionality, such as AXFR/IXFR zone transfers or dynamic DNS updates.
8. The attacker exfiltrates zone data or modifies DNS records, depending on the enabled functionality.

## Impact

Successful exploitation of this vulnerability can allow unauthenticated attackers to perform unauthorized actions on the affected CoreDNS server. This can lead to the exposure of sensitive zone data via AXFR/IXFR, unauthorized modification of DNS records through dynamic updates, or other bypasses of TSIG-gated plugin behavior. The DoH and DoH3 variants pose a higher risk because they do not even require a valid TSIG key name to be known. The impact depends on the specific TSIG-protected functionality enabled on the CoreDNS server and the sensitivity of the data being protected.

## Recommendation

- Upgrade CoreDNS to version 1.14.3 or later to patch CVE-2026-35579.
- If upgrading is not immediately possible, disable gRPC, QUIC, DoH, and DoH3 listeners where TSIG authentication is required as suggested in the advisory.
- Implement network-level access controls to restrict access to gRPC, QUIC, DoH, and DoH3 ports to trusted sources only, as recommended in the advisory.
- Deploy the Sigma rule "Detect CoreDNS AXFR Request over DoH with Forged TSIG" to identify potential exploitation attempts.
