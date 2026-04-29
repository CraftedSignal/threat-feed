---
title: CoreDNS TSIG Authentication Bypass Vulnerability
slug: 2024-01-coredns-tsig-bypass
description: A vulnerability exists in CoreDNS' tsig plugin that allows bypassing TSIG authentication on non-plain-DNS transports like DoT, DoH, DoH3, DoQ, and gRPC due to trusting the transport writer's TsigStatus() instead of performing verification itself, enabling unauthenticated remote clients to bypass TSIG-based authentication/authorization.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve
  - vulnerability
  - coredns
  - authentication-bypass
vendors:
  - CoreDNS
products:
  - CoreDNS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-qhmp-q7xh-99rh
rules:
  - title: Detect CoreDNS TSIG Bypass Attempt
    description: Detects attempts to bypass TSIG authentication in CoreDNS by monitoring DNS query responses over DoT/DoH with unexpected NOERROR responses and a non-zero answer count after a REFUSED response when TSIG is expected.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555.003
    data_sources:
      - dns_query
      - coredns
  - title: Detect CoreDNS DoH Request with Invalid TSIG
    description: Detects DoH requests to CoreDNS where the HTTP response indicates a successful request (200) but the DNS response code is NOERROR and the answer count is greater than 0, which is indicative of a TSIG bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1555.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability has been identified in CoreDNS' tsig plugin affecting versions prior to 1.14.3. This flaw enables attackers to bypass TSIG (Transaction Signature) authentication on non-plain-DNS transports, including DoT (DNS over TLS), DoH (DNS over HTTPS), DoH3, DoQ, and gRPC. The vulnerability stems from the plugin's reliance on the transport writer's `TsigStatus()` function instead of performing independent TSIG verification. This trust allows clients without the correct shared secret to bypass `require all` restrictions. The vulnerability matters because it allows unauthorized access to restricted DNS resources, potentially exposing sensitive zone data and enabling privileged queries that would normally be protected by TSIG authentication.

## Attack Chain

1. An attacker crafts a DNS request with an invalid TSIG signature.
2. The attacker sends the crafted DNS request to a CoreDNS server configured to use DoT, DoH, DoH3, DoQ, or gRPC.
3. The CoreDNS server receives the request and the tsig plugin is invoked.
4. The tsig plugin checks the validity of the TSIG signature by calling the transport writer's `TsigStatus()` function.
5. Because the transport writer (e.g., `DoHWriter`, `DoT`, `DoQWriter`, `gRPCresponse`) does not perform TSIG verification and always returns a nil or "valid" status, the plugin incorrectly assumes the TSIG signature is valid.
6. The CoreDNS server processes the DNS request as if it were authenticated, bypassing the intended TSIG-based authorization.
7. The attacker gains unauthorized access to protected zone data, privileged queries, or other restricted resources.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote clients to bypass TSIG-based authentication/authorization on encrypted transports. This can lead to unauthorized access to sensitive zone data, the execution of privileged queries, and other actions that the deployment intended to restrict behind `tsig { require all }`. The impact is significant as it undermines the security measures designed to protect critical DNS resources.

## Recommendation

*   Upgrade CoreDNS to version 1.14.3 or later to patch CVE-2026-33190.
*   Monitor network traffic for DNS queries over DoT, DoH, DoH3, DoQ, and gRPC that exhibit characteristics of TSIG bypass attempts. Use the Sigma rule `Detect CoreDNS TSIG Bypass Attempt` to identify such attempts.
*   Regularly review and validate TSIG configurations to ensure they are properly enforced across all DNS transports.
