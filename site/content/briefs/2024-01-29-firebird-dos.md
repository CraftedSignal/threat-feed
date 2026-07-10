---
title: Firebird Server Denial-of-Service via Out-of-Order Authentication Segments
slug: 2024-01-29-firebird-dos
description: An unauthenticated attacker can crash Firebird database servers prior to versions 5.0.4, 4.0.7 and 3.0.14 by sending out-of-order CNCT_specific_data segments during the authentication process, leading to a denial-of-service condition.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - dos
  - firebird
vendors:
  - Firebird
products:
  - Firebird
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-27890
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27890
rules:
  - title: Detect Firebird Authentication Attempt
    description: Detects initial connection attempts to the Firebird database server on the default port 3050, which could be related to CVE-2026-27890 exploitation.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - network_connection
      - windows
  - title: Detect Multiple Connections to Firebird Server
    description: Detects multiple connection attempts to the Firebird database server from the same source IP address, potentially indicating a scan or denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Firebird is a widely used open-source relational database management system. A vulnerability exists in versions prior to 5.0.4, 4.0.7, and 3.0.14 related to the processing of CNCT_specific_data segments during the authentication handshake. The Firebird server incorrectly assumes that these segments will arrive in strictly ascending order. An attacker who can establish a network connection to the Firebird server (knowing the IP address and port) can send crafted authentication packets with out-of-order segments. This causes the `Array` class's `grow()` method to compute a negative size, resulting in a SIGSEGV crash and subsequent denial-of-service. This vulnerability allows for easy remote exploitation without requiring any valid credentials, making patching a priority.

## Attack Chain

1.  Attacker identifies a vulnerable Firebird server by scanning for the default port (3050).
2.  Attacker initiates a TCP connection to the Firebird server on port 3050.
3.  The attacker sends a CNCT_protocol message to initiate the authentication process.
4.  The attacker sends CNCT_specific_data segments within the authentication packet, intentionally sending them out of order (e.g., segment 2 before segment 1).
5.  The Firebird server receives the out-of-order CNCT_specific_data segments and attempts to process them.
6.  Within the `Array` class's `grow()` method, a negative size value is calculated due to the incorrect segment order.
7.  The `grow()` method attempts to allocate a negative-sized array, triggering a SIGSEGV signal.
8.  The Firebird server process crashes, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition on the Firebird server. This can disrupt critical applications relying on the database, causing data unavailability and potential data loss due to unsaved transactions. The impact is significant because the vulnerability is remotely exploitable without authentication, potentially affecting any exposed Firebird instance. The number of potential victims is difficult to quantify but includes any organization running vulnerable Firebird versions.

## Recommendation

*   Immediately upgrade Firebird servers to versions 5.0.4, 4.0.7, or 3.0.14 to patch CVE-2026-27890.
*   Deploy the Sigma rule `Detect Firebird Authentication Attempt` to detect potential exploitation attempts by monitoring network connections to port 3050.
*   Consider implementing network segmentation to limit exposure of Firebird servers to untrusted networks.
*   Implement rate limiting on connections to the Firebird server port to mitigate the impact of rapid connection attempts.
