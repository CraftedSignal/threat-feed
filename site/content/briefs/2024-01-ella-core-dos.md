---
title: Ella Core NGAP Message Handling Vulnerability Leads to Denial of Service
slug: 2024-01-ella-core-dos
description: Ella Core versions prior to 1.6.0 are vulnerable to a denial-of-service attack where a crafted NGAP LocationReport message with a missing `UEPresenceInAreaOfInterestList` can crash the process, disrupting service for all connected subscribers.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - denial-of-service
  - 5G
  - ellacore
vendors:
  - Ella Core
products:
  - Ella Core
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33282
rules:
  - title: Detect Malformed NGAP LocationReport Messages
    description: Detects NGAP LocationReport messages with missing UEPresenceInAreaOfInterestList IE which can cause a denial of service.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
  - title: Detect High Volume of NGAP Traffic to Ella Core
    description: Detects a sudden increase in NGAP traffic volume to an Ella Core instance, which could indicate a DoS attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
  - title: Detect Malformed NGAP Messages via Protocol Decoding Errors
    description: Detects malformed NGAP messages based on protocol decoding errors, which can indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

Ella Core, a 5G core designed for private networks, is susceptible to a denial-of-service (DoS) vulnerability in versions prior to 1.6.0. This flaw, identified as CVE-2026-33282, stems from improper handling of malformed Next Generation Application Protocol (NGAP) LocationReport messages. Specifically, if the `ue-presence-in-area-of-interest` event type is present without the optional `UEPresenceInAreaOfInterestList` information element (IE), the Ella Core process panics. An attacker, without requiring authentication, can exploit this by sending specially crafted NGAP messages to the vulnerable Ella Core instance. Successful exploitation results in a crash of the Ella Core process, leading to service disruption for all connected subscribers. The vendor addressed this vulnerability in version 1.6.0 by implementing IE presence verification in NGAP message handling.

## Attack Chain

1. The attacker identifies a vulnerable Ella Core instance running a version prior to 1.6.0.
2. The attacker crafts a malicious NGAP LocationReport message.
3. The crafted message includes the `ue-presence-in-area-of-interest` event type.
4. Crucially, the `UEPresenceInAreaOfInterestList` information element (IE) is omitted from the message.
5. The attacker sends the crafted NGAP message to the vulnerable Ella Core instance.
6. Upon receiving the malformed message, the Ella Core process attempts to parse the missing `UEPresenceInAreaOfInterestList` IE.
7. Due to the missing IE, the parsing operation fails, causing a panic within the Ella Core process.
8. The Ella Core process crashes, leading to a denial of service condition for all connected subscribers.

## Impact

Successful exploitation of CVE-2026-33282 leads to a denial-of-service condition affecting all subscribers connected to the vulnerable Ella Core instance. This can disrupt critical communication services in private 5G networks, potentially impacting industrial control systems, healthcare facilities, or other environments relying on uninterrupted connectivity. The severity is high due to the ease of exploitation (no authentication required) and the potential for widespread service disruption.

## Recommendation

*   Upgrade Ella Core instances to version 1.6.0 or later to patch CVE-2026-33282.
*   Deploy the Sigma rule `Detect Malformed NGAP LocationReport Messages` to identify potentially malicious NGAP messages being sent to Ella Core instances.
*   Implement network-level filtering to block or rate-limit NGAP traffic from suspicious sources.
