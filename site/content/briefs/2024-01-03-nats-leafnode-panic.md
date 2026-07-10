---
title: NATS Server Pre-Authentication Denial-of-Service via Leafnode Handling
slug: 2024-01-03-nats-leafnode-panic
description: A pre-authentication denial-of-service vulnerability exists in NATS servers before versions v2.12.6 and v2.11.15, allowing a remote client connected to the leafnode port to crash the server by sending a malformed message.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nats
  - denial-of-service
  - leafnode
vendors:
  - NATS
products:
  - NATS Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-vprv-35vv-q339
  - https://advisories.nats.io/CVE/secnote-2026-10.txt
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-33218
rules:
  - title: Detect Connection Attempts to Leafnode Port
    description: Detects connections to the default NATS leafnode port (7422), which could indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - impact
      - initial_access
    data_sources:
      - network_connection
      - linux
  - title: Detect Sudden NATS Server Process Termination
    description: Detects unexpected NATS server process termination, which could indicate a crash due to exploitation of CVE-2026-33218.  Requires process accounting or auditd.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

NATS.io is a high-performance open-source pub-sub distributed communication technology widely used for cloud, on-premise, IoT, and edge computing environments. NATS servers utilize "leafnode" connections to enable hub/spoke topologies with other NATS servers. A critical vulnerability has been discovered affecting NATS servers prior to versions v2.12.6 and v2.11.15. This flaw allows an unauthenticated client capable of connecting to the leafnode port to trigger a server panic, resulting in a denial-of-service condition. This vulnerability, identified as CVE-2026-33218, highlights the importance of securing NATS deployments and promptly applying available patches or workarounds to prevent potential service disruptions.

## Attack Chain

1. An attacker identifies a vulnerable NATS server with an exposed leafnode port.
2. The attacker establishes a network connection to the leafnode port (typically 7422).
3. The attacker sends a specially crafted, malformed message to the leafnode port. This message is designed to exploit a flaw in the pre-authentication handling of leafnode connections.
4. The NATS server attempts to process the malformed message without proper validation.
5. Due to the malformed nature of the message, a panic occurs within the NATS server's code, specifically related to leafnode message processing.
6. The panic causes the NATS server process to terminate abruptly.
7. The NATS server becomes unavailable, disrupting any applications or services relying on it.
8. This denial-of-service condition persists until the NATS server is manually restarted, and further attacks can repeat the process.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition affecting the NATS server. The impact scope depends on the criticality of the NATS server within the affected environment. Services relying on the NATS server for communication will become unavailable, potentially disrupting business operations. The vulnerability affects all environments using vulnerable NATS server instances, including cloud deployments, on-premise installations, and edge computing scenarios. Widespread exploitation could result in significant operational disruptions across various sectors relying on NATS for real-time data streaming and messaging.

## Recommendation

*   Immediately upgrade NATS servers to version v2.12.6 or v2.11.15 or later to patch CVE-2026-33218.
*   If upgrading is not immediately feasible, disable leafnode support on NATS servers if it is not required, mitigating the attack vector.
*   Restrict network connections to the leafnode port (default 7422) using firewalls or network access control lists, limiting potential attackers.
*   Monitor network connections to the leafnode port for unexpected or unauthorized access attempts, using network connection logs.
