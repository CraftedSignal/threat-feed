---
title: NATS Server Panic via Malicious Compression on Leafnode Port
slug: 2024-01-09-nats-server-panic
description: A vulnerability exists in NATS servers configured to accept leafnode connections where a malicious remote NATS server can trigger a server panic by exploiting compression negotiation on the leafnode port.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nats
  - denial-of-service
  - compression
vendors:
  - NATS
products:
  - NATS server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://github.com/advisories/GHSA-52jh-2xxh-pwh6
iocs:
  - type: port
    value: "7422"
ioc_counts:
  port: 1
rules:
  - title: Detect Connections to NATS Leafnode Port
    description: Detects connections to the default NATS leafnode port (7422). Modify the DestinationPort value if a custom port is configured.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
  - title: Detect Connections to NATS Leafnode Port - Linux
    description: Detects connections to the default NATS leafnode port (7422) on Linux systems.  Modify the DestinationPort value if a custom port is configured.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

NATS.io is a high-performance open-source pub-sub distributed communication technology. A vulnerability exists when a NATS server is configured to accept leafnode connections, which is not the default setting. In this configuration, a malicious remote NATS server can trigger a server panic by exploiting the compression negotiation process on the leafnode port (default 7422). This vulnerability, identified as CVE-2026-29785, occurs pre-authentication, meaning an attacker does not need valid credentials. The vulnerability affects NATS server versions prior to v2.11.14 and versions between v2.12.0-RC.1 and v2.12.5. Defenders should disable compression on the leafnode port to mitigate this risk.

## Attack Chain

1.  The attacker identifies a NATS server with leafnode configuration enabled and compression active on port 7422.
2.  The attacker establishes a connection to the leafnode port (7422) of the target NATS server.
3.  The attacker initiates a compression negotiation handshake with the target server.
4.  The attacker sends a crafted message during the compression negotiation, designed to exploit a vulnerability in the NATS server's compression handling logic.
5.  The NATS server attempts to process the malicious compression data.
6.  Due to the crafted nature of the data, the NATS server's compression library triggers a panic.
7.  The NATS server process terminates abruptly due to the panic.
8.  The NATS server becomes unavailable, disrupting NATS-based communication.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service (DoS) condition. Any NATS server configured to accept leafnode connections is vulnerable. This could impact cloud, on-premise, IoT, and edge computing environments using NATS for inter-service communication. The exact number of affected systems is unknown, but the impact is significant as it can disrupt critical communication pathways.

## Recommendation

*   Disable compression on the leafnode port by setting `compression: off` in the NATS server configuration file as described in the advisory to remediate CVE-2026-29785.
*   Monitor network connections to port 7422, the default leafnode port, for unexpected connection attempts from untrusted sources (refer to the IOC table).
*   Deploy the Sigma rule to detect connections to the leafnode port with unexpected client IP addresses.
