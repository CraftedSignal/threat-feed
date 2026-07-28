---
title: QTINeon NeonRelay Unauthenticated Denial-of-Service Amplification Vulnerability
slug: 2026-07-qtineon-unauthenticated-relay-dos
description: An unauthenticated attacker can exploit an unbounded RECONNECT_REQUEST forwarding vulnerability in QTINeon's NeonRelay component to amplify denial-of-service attacks against a connected host. By sending spoofed RECONNECT_REQUEST packets, the relay forwards each one to the host without proper deduplication or rate limiting, consuming host resources. Additionally, excessive spoofed IPs can reset legitimate rate limiting, further impacting service availability. This vulnerability affects Java, Python, and TypeScript implementations of NeonRelay.
date: "2026-07-28T16:38:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - amplification
  - network
  - vulnerability
vendors:
  - QuietTerminal
products:
  - qti-neon = 1.0.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The host receives one forwarded packet per spoofed source per cleanup cycle, making the relay an amplification vector for denial-of-service against the host.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The host receives one forwarded packet per spoofed source per cleanup cycle, making the relay an amplification vector for denial-of-service against the host.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 'A secondary issue: once more than `maxRateLimiters` spoofed IPs are seen, `performCleanup` calls `rateLimiters.clear()`, resetting rate limit state for all sources including legitimate ones.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-85rg-p3fr-xc2f
---

A high-severity denial-of-service amplification vulnerability, identified as CVE-2026-54609, exists within the `NeonRelay` component of QTINeon across its Java, Python, and TypeScript implementations (all versions 1.0.0). This flaw allows an unauthenticated attacker to leverage the relay to overwhelm a connected host by sending specially crafted `RECONNECT_REQUEST` packets. The relay's reconnect handler forwards these requests to the host without proper deduplication or size limitations on its `pendingReconnects` map, unlike the existing safeguards in the connect flow. An attacker, knowing a valid session ID, can send numerous `RECONNECT_REQUEST` packets with spoofed source IP addresses. Each unique spoofed IP receives a fresh token bucket, rendering the per-source rate limiter ineffective and turning the relay into a potent DoS amplification vector against the backend host. Furthermore, the handling of an excessive number of spoofed IPs can lead to the clearing of legitimate rate limit states, exacerbating the impact.

## Attack Chain

1. An unauthenticated attacker identifies a target QTINeon NeonRelay instance and obtains a valid session ID.
2. The attacker crafts numerous `RECONNECT_REQUEST` packets, each originating from a different, spoofed source IP address.
3. These spoofed `RECONNECT_REQUEST` packets are sent to the vulnerable `NeonRelay` instance.
4. The `NeonRelay` instance receives the packets and, due to the vulnerability, forwards each unique `sessionId:clientId` key (from a new spoofed source) to the backend host without checking for existing pending reconnects or enforcing a size cap.
5. Each forwarded packet triggers a new reconnect attempt on the host, consuming its resources for processing these requests.
6. As the number of spoofed IPs exceeds `maxRateLimiters`, the relay's `performCleanup` function clears all rate limiting states, including for legitimate clients, leading to further resource exhaustion and potential service disruption.
7. The host becomes overwhelmed, leading to a denial-of-service condition for legitimate users, with the relay acting as an amplification point.

## Impact

Successful exploitation of CVE-2026-54609 enables an unauthenticated attacker to execute a denial-of-service attack against the backend host connected via the vulnerable `NeonRelay`. The amplification nature of the vulnerability means a relatively small number of attacker-initiated packets can generate a large volume of traffic and processing load on the target host. This can lead to resource exhaustion, degradation of service, or complete unavailability for legitimate users. The vulnerability also poses a secondary risk where the clearing of all rate limit states can reset protections for legitimate traffic, making the host more susceptible to other forms of attack or simple overload. Given the relay's design prevents direct client exposure to the host's real address, this amplification path is the primary DoS vector. All three implementations of `NeonRelay` (Java, Python, TypeScript) are affected.

## Recommendation

* Implement network-level filtering to drop packets with spoofed source addresses (BCP38/uRPF) to partially mitigate the amplification path.
* Monitor for an unusually high volume of `RECONNECT_REQUEST` packets or a rapid increase in the number of unique source IPs attempting to reconnect through the `NeonRelay` component.
* Apply patches for CVE-2026-54609 immediately once they become available from QuietTerminal for all affected `qti-neon` versions across Java, Python, and TypeScript implementations.
* If possible, implement application-level rate limiting on the number of unique `sessionId:clientId` reconnect attempts processed by the `NeonRelay` to prevent the `pendingReconnects` map from growing unbounded as referenced in CVE-2026-54609.
