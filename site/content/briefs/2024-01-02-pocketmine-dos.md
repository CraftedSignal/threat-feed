---
title: PocketMine-MP ModalFormResponsePacket Denial-of-Service
slug: 2024-01-02-pocketmine-dos
description: A vulnerability in PocketMine-MP servers allows an attacker to cause a denial-of-service by sending a malformed ModalFormResponsePacket containing an excessively large JSON payload, impacting server performance and availability.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pocketmine-mp
  - denial-of-service
  - minecraft
vendors:
  - PocketMine
products:
  - PocketMine-MP
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-788v-5pfp-93ff
rules:
  - title: Detect Large ModalFormResponsePacket
    description: Detects abnormally large ModalFormResponsePackets indicative of a denial-of-service attempt in PocketMine-MP.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - unknown
  - title: Detect Multiple ModalFormResponsePacket from same IP
    description: Detects multiple ModalFormResponsePacket from the same IP address, which indicates a DoS attack.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - unknown
rules_count: 2
---

PocketMine-MP, a popular server software for Minecraft: Bedrock Edition, is susceptible to a denial-of-service (DoS) vulnerability due to insufficient validation of `ModalFormResponsePacket` data. An attacker can exploit this by sending a crafted packet containing an extremely large JSON payload within the `formData` field. This causes the server to consume excessive CPU and memory resources while attempting to parse the oversized JSON, potentially leading to unresponsiveness or complete server failure. The vulnerability affects PocketMine-MP servers running versions prior to 5.39.2. Exploitation requires a player to establish a full session on the server. The issue was patched with size limitations on form responses (cef1088341e40ee7a6fa079bca47a84f3524d877) and preventing decoding of responses with invalid form IDs (f983f4f66d5e72d7a07109c8175799ab0ee771d5).

## Attack Chain

1.  The attacker connects to a vulnerable PocketMine-MP server as a legitimate player.
2.  The attacker establishes a full session by spawning into the game world.
3.  The attacker crafts a `ModalFormResponsePacket` using a modified client or packet-sending script.
4.  The `formId` field in the packet is set to an invalid or non-existent form ID (e.g., 9999).
5.  The `formData` field is populated with an extremely large JSON array (e.g., 10+ MB payload, such as `[0,0,0,...]`).
6.  The attacker sends the crafted `ModalFormResponsePacket` to the server.
7.  The server receives the packet and attempts to parse the oversized JSON payload in the `formData` field, despite the invalid `formId`.
8.  The server consumes excessive CPU and memory resources during JSON parsing, leading to performance degradation or a complete freeze, resulting in a denial-of-service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition on the affected PocketMine-MP server. The server becomes unresponsive, preventing legitimate players from connecting or continuing their gameplay. The number of affected users depends on the server's player capacity. Unpatched servers are vulnerable to resource exhaustion attacks that can severely impact the game experience and potentially require a server restart. All sectors relying on public Minecraft: Bedrock Edition servers are potentially at risk.

## Recommendation

*   Upgrade PocketMine-MP servers to version 5.39.2 or later to apply the patches that address the vulnerability (cef1088341e40ee7a6fa079bca47a84f3524d877 and f983f4f66d5e72d7a07109c8175799ab0ee771d5).
*   Implement rate limiting on `ModalFormResponsePacket` processing to mitigate the impact of large packet floods (network_connection).
*   Deploy the Sigma rule provided below to detect suspicious `ModalFormResponsePacket` sizes indicative of exploitation attempts (network_connection).
