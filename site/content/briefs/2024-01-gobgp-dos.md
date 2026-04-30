---
title: GoBGP Remote Denial of Service via Malformed BGP Update Message
slug: 2024-01-gobgp-dos
description: A denial-of-service vulnerability exists in GoBGP version 4.3.0 where a malformed BGP UPDATE message containing an unrecognized Well-known Path Attribute triggers a nil pointer dereference, causing the BGP daemon to crash.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gobgp
  - dos
  - bgp
  - routing
vendors:
  - GoBGP
products:
  - GoBGP
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-7235-89m6-f4px
rules:
  - title: Detect GoBGP Malformed BGP Update
    description: Detects BGP UPDATE messages with unrecognized Well-known Path Attributes, potentially indicating a DoS attack against GoBGP.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - zeek
  - title: Detect GoBGP Crash via System Logs
    description: Detects GoBGP process crashes indicated by specific error messages in system logs.
    platform: sigma
    severity: critical
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - system
      - linux
rules_count: 2
---

GoBGP version 4.3.0 is susceptible to a denial-of-service (DoS) vulnerability triggered by malformed BGP UPDATE messages. Specifically, when GoBGP receives an UPDATE message containing an unrecognized Path Attribute marked as "Well-known" (Optional bit set to 0), the daemon fails to properly handle the error. This leads to a nil pointer dereference, resulting in a panic and subsequent crash of the entire GoBGP process. This vulnerability, disclosed in GHSA-7235-89m6-f4px, can be exploited by any BGP peer, internal or external, sending such a malformed message. This poses a significant risk to network stability as it can disrupt BGP routing and connectivity.

## Attack Chain

1. An attacker establishes a standard BGP session with the targeted GoBGP instance, completing the OPEN/KEEPALIVE exchange.
2. The attacker crafts a malicious BGP UPDATE message.
3. This UPDATE message includes a Path Attribute with the Optional bit set to 0 (Well-known).
4. The Path Attribute Type Code is set to an unrecognized value (e.g., 0xEE or 0xFF).
5. The parsing logic in GoBGP identifies the unrecognized Well-known attribute.
6. The `recvMessageloop` function in `pkg/server/fsm.go` fails to halt execution after identifying the malformed attribute.
7. The code attempts to dereference a nil pointer associated with the invalid message body.
8. This results in a "panic: runtime error: invalid memory address or nil pointer dereference", causing the GoBGP daemon to crash, disrupting BGP routing.

## Impact

The vulnerability allows a remote attacker to cause a denial-of-service condition on GoBGP deployments. A single malformed UPDATE message is sufficient to trigger the crash, affecting all GoBGP instances peering with potentially malicious or compromised BGP speakers. This can lead to routing instability, network outages, and potential data plane disruptions. The affected version, 4.3.0, may be widely deployed in various network environments, making it a significant concern for network operators.

## Recommendation

*   Deploy the Sigma rule `Detect GoBGP Malformed BGP Update` to identify crafted BGP UPDATE messages containing unrecognized Well-known Path Attributes via network traffic analysis.
*   Monitor BGP peer sessions for unexpected disconnects or restarts, which may indicate exploitation of this vulnerability.
*   Consider implementing BGP route filtering and validation mechanisms to mitigate the impact of malformed or malicious UPDATE messages.
