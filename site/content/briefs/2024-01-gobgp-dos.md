---
title: GoBGP Remote Denial of Service via Malformed BGP Update Message
slug: 2024-01-gobgp-dos
description: GoBGP version 4.4.0 is vulnerable to a remote denial-of-service attack where a malformed BGP UPDATE message triggers a nil pointer dereference, crashing the GoBGP process.
date: "2024-01-09T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - bgp
  - denial-of-service
  - networking
vendors:
  - osrg
products:
  - gobgp/v4 (4.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-p3w2-64xm-833j
rules:
  - title: Detect GoBGP Crash via Nil Pointer Dereference
    description: Detects GoBGP crashes resulting from nil pointer dereference during BGP update processing.
    platform: sigma
    severity: critical
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
  - title: Detect Malformed BGP Update Messages
    description: Detects malformed BGP Update messages by analyzing GoBGP log data for specific warning messages related to attribute validation failures.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

GoBGP version 4.4.0 is susceptible to a denial-of-service (DoS) vulnerability that can be exploited by unauthenticated remote BGP peers. This flaw arises from improper handling of malformed BGP UPDATE messages, specifically those containing inconsistent attribute lengths. When a GoBGP server receives such a message, it incorrectly transitions to a "withdraw" action, leading to a nil pointer dereference in the `AdjRib.Update` function. This dereference causes a fatal panic, crashing the entire GoBGP process and resulting in a complete loss of BGP service availability. This vulnerability allows an attacker to disrupt network routing and potentially cause significant network outages.

## Attack Chain

1. An unauthenticated remote BGP peer establishes a BGP connection with the vulnerable GoBGP server.
2. The attacker crafts a malicious BGP UPDATE message with inconsistent attribute lengths.
3. The crafted UPDATE message is sent to the GoBGP server over the established BGP session.
4. The `handleUpdate` function in `pkg/server/peer.go` processes the received message.
5. Due to the malformed attributes, the message is treated as a withdrawal.
6. The `AdjRib.Update` function in `internal/pkg/table/adj.go` is called.
7. At line 127 of `adj.go`, the code attempts to access a member of a nil pointer, causing a panic.
8. The GoBGP process crashes, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability results in a complete denial of BGP service, as the GoBGP process crashes. This can disrupt network routing, potentially leading to significant network outages and impacting any services relying on BGP. The vulnerability affects GoBGP version 4.4.0. While the exact number of affected installations is unknown, any network relying on a vulnerable GoBGP instance is at risk.

## Recommendation

*   Upgrade to a patched version of GoBGP that addresses CVE-2026-42285.
*   Implement the Sigma rule "Detect GoBGP Crash via Nil Pointer Dereference" to detect exploitation attempts in real-time based on log messages.
*   Monitor BGP sessions from IP 192.168.31.195, as this address was involved in the proof-of-concept exploit.
*   Deploy the Sigma rule "Detect Malformed BGP Update Messages" to identify potentially malicious BGP UPDATE messages.
