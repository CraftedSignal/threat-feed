---
title: Firebird Server Denial-of-Service Vulnerability (CVE-2026-28224)
slug: 2026-04-firebird-dos
description: An unauthenticated attacker can trigger a denial-of-service condition on vulnerable Firebird servers by sending a specially crafted op_crypt_key_callback packet, leading to a null pointer dereference and server crash.
date: "2026-04-18T10:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-28224
  - denial-of-service
  - firebird
  - database
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-28224
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28224
rules:
  - title: Detect Unauthenticated Firebird Crypt Callback
    description: Detects attempts to exploit CVE-2026-28224 by identifying unauthenticated op_crypt_key_callback packets sent to Firebird servers.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Firebird Server Crash
    description: Detects potential Firebird server crashes by monitoring for process termination events with specific exit codes indicative of a crash.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-28224 describes a denial-of-service vulnerability affecting Firebird, an open-source relational database management system. The vulnerability exists in versions prior to 5.0.4, 4.0.7, and 3.0.14. An unauthenticated attacker can exploit this vulnerability by sending a crafted `op_crypt_key_callback` packet to the server. When the server receives this packet without prior authentication, the `port_server_crypt_callback` handler is not initialized, resulting in a null pointer dereference. This leads to a server crash, effectively causing a denial-of-service condition. The attacker only needs to know the server's IP address and port to trigger this vulnerability. The vulnerability has been patched in Firebird versions 5.0.4, 4.0.7 and 3.0.14.

## Attack Chain

1.  The attacker identifies a vulnerable Firebird server by scanning for exposed ports (typically 3050).
2.  The attacker establishes a TCP connection with the targeted Firebird server on the identified port.
3.  The attacker crafts a malicious `op_crypt_key_callback` packet. This packet does not require prior authentication.
4.  The attacker sends the crafted `op_crypt_key_callback` packet to the Firebird server.
5.  Upon receiving the packet, the server attempts to process the request in the `port_server_crypt_callback` handler.
6.  Because no prior authentication has occurred, the `port_server_crypt_callback` handler is not properly initialized, leading to a null pointer dereference.
7.  The null pointer dereference causes the Firebird server process to crash.
8.  The Firebird database server becomes unavailable, resulting in a denial-of-service condition for legitimate users.

## Impact

Successful exploitation of CVE-2026-28224 results in a denial-of-service condition, rendering the Firebird database server unavailable. This can disrupt applications and services that rely on the database, leading to data access issues, application downtime, and potential data loss if proper backup and recovery mechanisms are not in place. The number of affected organizations depends on the prevalence of vulnerable Firebird versions and their exposure to the network.

## Recommendation

*   Upgrade Firebird servers to versions 5.0.4, 4.0.7, or 3.0.14 or later to patch CVE-2026-28224.
*   Deploy the Sigma rule "Detect Unauthenticated Firebird Crypt Callback" to your SIEM to identify potential exploitation attempts targeting this vulnerability.
*   Implement network segmentation and access control lists (ACLs) to restrict access to Firebird servers from untrusted networks, mitigating the risk of unauthorized exploitation (network_connection logs).
*   Monitor network traffic for suspicious `op_crypt_key_callback` packets being sent to Firebird servers, particularly from untrusted sources (network_connection logs).
