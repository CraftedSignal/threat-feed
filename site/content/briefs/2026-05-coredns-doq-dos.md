---
title: CoreDNS DoQ Server Denial-of-Service Vulnerability
slug: 2026-05-coredns-doq-dos
description: CoreDNS' DNS-over-QUIC (DoQ) server can be driven into large goroutine and memory growth by a remote client that opens many QUIC streams and stalls after sending only 1 byte, leading to denial of service in versions before 1.14.3.
date: "2026-04-28T22:41:50Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - coredns
  - dos
  - denial-of-service
  - vulnerability
vendors:
  - coredns
products:
  - coredns
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
  - tactic_id: TA0011
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2025-47950
    cvss: 7.5
    epss: 0.00151
references:
  - https://github.com/advisories/GHSA-2wpx-qpw2-g5h5
rules:
  - title: Detect CoreDNS Excessive Goroutine Growth
    description: Detects a rapid increase in the number of goroutines in a CoreDNS process, which may indicate a DoS attack exploiting CVE-2026-32934.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
  - title: Detect CoreDNS DoQ Connection Flood
    description: Detects a high number of network connections to the CoreDNS DoQ port (853), which may indicate a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in CoreDNS' DNS-over-QUIC (DoQ) server implementation. A remote, unauthenticated attacker can exploit this flaw by opening numerous QUIC streams and sending only a single byte, causing the server to exhaust memory resources. This occurs because CoreDNS spawns a goroutine per accepted stream, even when the worker pool is full, and workers can block indefinitely when reading incomplete DoQ messages. The vulnerability is present in CoreDNS versions prior to 1.14.3. The root cause is an incomplete fix/regression for CVE-2025-47950, highlighting the risk of regressions in security patches. This can lead to service outages and impacts DNS resolution availability for affected systems.

## Attack Chain

1.  The attacker establishes multiple QUIC connections to the CoreDNS server on the DoQ port (default 853).
2.  For each connection, the attacker opens a large number of QUIC streams.
3.  On each stream, the attacker sends only the first byte of the 2-byte length prefix expected for a DoQ message.
4.  The CoreDNS server accepts each stream and spawns a goroutine to handle it, regardless of worker pool capacity. These goroutines wait for a worker token.
5.  The worker goroutines attempt to read the full 2-byte length prefix using `io.ReadFull()`, blocking indefinitely because the second byte is never sent by the attacker.
6.  As the attacker opens more streams, the backlog of waiting goroutines grows without bound, consuming memory.
7.  The server's memory usage increases rapidly, potentially leading to an OOM-kill.
8.  The CoreDNS service becomes unavailable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition on the CoreDNS server. The server experiences excessive memory consumption and goroutine growth, potentially leading to an OOM-kill and service outage. The number of victims depends on the deployment size and exposure of the CoreDNS server. All organizations using affected versions of CoreDNS are vulnerable. This impacts DNS resolution, potentially disrupting all network services that rely on the affected CoreDNS server.

## Recommendation

*   Upgrade CoreDNS to version 1.14.3 or later to patch CVE-2026-32934 and mitigate the DoS vulnerability.
*   Monitor CoreDNS server resource usage (CPU, memory, goroutine count) for anomalous spikes that could indicate exploitation.
*   Implement rate limiting or connection limits on the DoQ port (853) to reduce the impact of a potential attack.
*   Deploy the Sigma rule `Detect CoreDNS Excessive Goroutine Growth` to identify potential exploitation attempts.
