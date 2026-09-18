---
title: CoreDNS DoH/DoQ/gRPC RFC 2136 UPDATE Bypass
slug: 2026-09-coredns-dns-update-bypass
description: CoreDNS versions up to 1.14.6 fail to validate DNS UPDATE opcodes over DoH, DoH3, DoQ, and gRPC, allowing attackers to relay unauthorized updates to upstream servers.
date: "2026-09-18T01:11:17Z"
lastmod: "2026-09-18T01:11:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:coredns:coredns:*:*:*:*:*:*:*:*
tags:
  - dns
  - coredns
  - vulnerability
  - rfc-2136
  - denial-of-service
  - cve-2026-82399
  - networking
vendors:
  - CoreDNS
products:
  - CoreDNS (<= 1.14.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can use the 'proxy' or 'forward' plugin to relay unauthorized update requests to upstream DNS servers.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A successful attack can redirect traffic, take over names, alter mail routing, or disrupt the writable zone.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated client can use DNS name compression to make one 65,533-byte request allocate more than 10 MiB while it is unpacked. Concurrent requests can exhaust memory and terminate CoreDNS.
    confidence_band: high
cves:
  - id: CVE-2026-86003
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-9gm5-9rfh-m6vx
  - https://datatracker.ietf.org/doc/html/rfc2136
  - https://github.com/advisories/GHSA-mrg3-qvqr-jw29
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82399
rules:
  - title: Detect Potential CoreDNS DoS Attempt via Large Payloads
    description: Detects oversized DNS queries sent to web-based transport endpoints which may indicate attempts to trigger memory exhaustion in CoreDNS.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade CoreDNS to 1.14.7 or later
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies CoreDNS <= 1.14.6 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Enforce TSIG authentication on all authoritative upstream servers.
      owner: IT Operations
      addresses: CVE-2026-86003
      evidence: Requiring and validating end-to-end TSIG prevents the demonstrated attack.
updates:
  - at: "2026-09-18T01:11:37Z"
    level: L1
    summary: 'added detection rule: Detect Potential CoreDNS DoS Attempt via Large Payloads'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mrg3-qvqr-jw29
---

CoreDNS versions 1.14.6 and earlier contain a vulnerability where DNS-over-HTTPS (DoH), DNS-over-HTTPS3 (DoH3), DNS-over-QUIC (DoQ), and DNS-over-gRPC listeners do not enforce the same request policy applied to standard UDP and TCP listeners. Specifically, these modern transports failed to filter out RFC 2136 UPDATE messages. When CoreDNS is configured with the 'forward' or 'proxy' plugin, it forwards these unauthorized UPDATE messages to an upstream authoritative DNS server. 

If the upstream server is configured to trust requests originating from the CoreDNS server IP address or an authenticated session, the upstream will process these updates as legitimate requests from the proxy itself. This bypasses the need for the attacker to provide end-to-end TSIG authentication, enabling unauthorized modification, redirection, or deletion of DNS records in the target zone. Defenders should patch CoreDNS to the latest version to ensure UPDATE opcodes are rejected by these transports before plugin dispatch.

## Attack Chain

1. Attacker identifies a CoreDNS instance reachable via DoH, DoH3, DoQ, or gRPC.
2. Attacker crafts an RFC 2136 UPDATE packet targeting a zone hosted by an upstream DNS server configured behind the CoreDNS instance.
3. Attacker sends the malicious UPDATE packet to the target CoreDNS instance over one of the vulnerable transports (e.g., DoH).
4. The CoreDNS listener parses the message header without invoking `dns.DefaultMsgAcceptFunc` to validate the opcode.
5. The CoreDNS server dispatches the unauthorized UPDATE message to the 'forward' or 'proxy' plugin.
6. The 'forward' plugin encapsulates or relays the original UPDATE request to the upstream authoritative server.
7. The upstream server accepts the UPDATE, trusting the request due to the established connection or trusted source IP of the CoreDNS server.
8. The upstream server modifies the DNS record, leading to traffic redirection or zone disruption.

## Impact

Successful exploitation allows unauthenticated attackers to manipulate DNS infrastructure. By injecting or altering records, attackers can facilitate traffic redirection (man-in-the-middle), intercept sensitive data, disrupt mail delivery, or take over legitimate names. The scope of impact depends on the sensitivity of the zones managed by the upstream authoritative servers and whether they rely on the CoreDNS proxy for implicit trust.

## Recommendation

- Upgrade all instances of CoreDNS to a version containing the fix for CVE-2026-86003.
- Audit CoreDNS 'forward' and 'proxy' plugin configurations to ensure upstream servers require explicit TSIG authentication for all zones that accept dynamic updates.
- Monitor logs for unusual DNS UPDATE activity originating from CoreDNS infrastructure toward sensitive internal or external authoritative zones.
- Restrict access to DoH, DoQ, and gRPC endpoints to authorized clients at the network edge if these services are not required for public exposure.
