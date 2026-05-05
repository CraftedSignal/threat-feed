---
title: Hysteria Server Out-of-Memory Vulnerability via Malformed QUIC Packet
slug: 2024-01-02-hysteria-quic-oom
description: A specially constructed QUIC package can crash the Hysteria server due to an out-of-memory (OOM) condition when the 'sniff' option is enabled, leading to a denial of service.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - hysteria
  - quic
  - oom
  - dos
vendors:
  - apernet
products:
  - hysteria/core/v2 (<= 2.8.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-9fw6-xgg2-mq9q
rules:
  - title: Detect Hysteria Malicious QUIC Packet
    description: Detects a potential Hysteria OOM attack by identifying unusually large UDP packets sent to the Hysteria server when 'sniff' is enabled.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Hysteria Client UDP Connection
    description: Detects a new Hysteria client UDP connection by monitoring for initial UDP traffic on the server port.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Hysteria is a feature-rich network utility optimized for networks experiencing high packet loss. A vulnerability exists in Hysteria versions 2.8.1 and earlier that can be exploited by a user with a valid password. When the 'sniff' option is enabled on the Hysteria server, a malicious actor can send a specially crafted QUIC packet that triggers excessive memory allocation, leading to an out-of-memory (OOM) condition and subsequent denial of service. This attack vector allows a threat actor to exhaust server resources, disrupting legitimate network traffic and potentially impacting all users relying on the affected Hysteria server.

## Attack Chain

1. The attacker obtains a valid username and password for the Hysteria server.
2. The attacker connects to the Hysteria server using a Hysteria client.
3. The attacker establishes a UDP connection through the Hysteria client.
4. The attacker crafts a malicious QUIC packet designed to trigger excessive memory allocation. The packet contains a large crypto length field.
5. The attacker sends the malicious QUIC packet to the Hysteria server via the established UDP connection.
6. The Hysteria server receives the malicious QUIC packet and processes it due to the 'sniff' option being enabled.
7. The server attempts to allocate memory based on the oversized crypto length specified in the malicious packet.
8. The server exhausts available memory, resulting in an out-of-memory (OOM) condition and a denial-of-service state.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service (DoS) condition on the Hysteria server. All users relying on the server for network connectivity will experience disruption. The vulnerability requires a valid username and password, limiting the scope of potential attackers, but the impact on availability is significant. This vulnerability affects any Hysteria server with the 'sniff' option enabled.

## Recommendation

*   Upgrade to Hysteria version 2.8.2 or later to patch the vulnerability.
*   Disable the `sniff` option in the Hysteria server configuration (`server.yaml`) if it is not essential for your deployment to prevent this attack.
*   Deploy the Sigma rule "Detect Hysteria Malicious QUIC Packet" to identify potential exploitation attempts by monitoring for unusually large packet sizes on UDP connections (see 'rules' section).
*   Monitor server resource utilization, especially memory consumption, for anomalies that may indicate an ongoing attack.
