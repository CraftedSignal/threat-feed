---
title: PocketMine-MP LogDoS via Malformed Login Packet
slug: 2024-01-pocketmine-logdos
description: Attackers can cause a denial-of-service on PocketMine-MP servers by sending a crafted Minecraft LoginPacket containing large or complex structures in the clientData JWT body, leading to excessive logging and potential server crashes.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - minecraft
  - logdos
  - pocketmine-mp
  - denial-of-service
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
  - https://github.com/advisories/GHSA-h6rj-3m53-887h
rules:
  - title: Detect Minecraft Login Packets with Large ClientData
    description: Detects Minecraft Login Packets with unusually large clientData fields, which may indicate a LogDoS attempt.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Detect PocketMine-MP Excessive Logging
    description: Detects excessive logging activity from the PocketMine-MP server, potentially indicating a LogDoS attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A denial-of-service vulnerability affects PocketMine-MP servers due to insufficient validation of the `LoginPacket`. An attacker can exploit this by sending a specially crafted packet containing a large or complex JSON structure within the `clientData` JWT body's unknown properties. The PocketMine-MP server, versions prior to 5.4.1, processes this malformed data, generating excessively long log messages. This excessive logging consumes significant CPU resources and memory, and can ultimately lead to a crash due to the server attempting to serialize the large, offending data structure for logging. The issue stems from the JsonMapper instance being configured to warn instead of reject unexpected properties, which, while intended to accommodate changes from Microsoft, creates an exploitable vulnerability.

## Attack Chain

1. An attacker crafts a custom Minecraft client.
2. The client generates a `LoginPacket` to initiate a connection with the PocketMine-MP server.
3. Within the `LoginPacket`, the `clientData` field contains a JWT body.
4. The attacker injects a custom, unexpected JSON property (e.g., "invalid_key") into the JWT body of the `clientData`.
5. The value of the "invalid_key" is set to a large or complex object, such as a deeply nested array or an array with millions of elements.
6. The server receives the `LoginPacket` and processes the `clientData` JWT.
7. The server's JsonMapper encounters the unexpected "invalid_key" property.
8. The server's `warnUndefinedJsonPropertyHandler` attempts to serialize and log the large object value, leading to excessive resource consumption, and eventually an Out-of-Memory crash.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition on the PocketMine-MP server. The excessive logging can rapidly consume disk space and CPU resources, degrading server performance for legitimate users. In severe cases, the server may crash entirely due to memory exhaustion. This vulnerability affects PocketMine-MP servers exposed to public networks where unauthorized actors can send malicious login packets. The number of potential victims is any server running a vulnerable PocketMine-MP version (< 5.4.1) accessible to the public internet.

## Recommendation

*   Upgrade PocketMine-MP to version 5.4.1 or later to apply the patch that removes the vulnerable `var_export` and limits the logged property name length (reference: Patches section).
*   Implement a plugin that handles the `DataPacketReceiveEvent` to inspect `LoginPacket` data and use JsonMapper to reject packets with unusual properties. This will prevent the processing of malicious packets (reference: Workarounds section).
*   Monitor server logs for unusually long messages or repeated warnings about undefined JSON properties within clientData. This can be an indicator of exploitation attempts.
*   Deploy the provided Sigma rule to detect connection attempts with unusually large client data in the login packet.
