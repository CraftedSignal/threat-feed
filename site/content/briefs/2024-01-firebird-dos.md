---
title: Firebird Database Server Denial-of-Service Vulnerability (CVE-2026-28212)
slug: 2024-01-firebird-dos
description: An unauthenticated attacker can cause a denial-of-service condition on vulnerable Firebird database servers by sending a specially crafted network packet that triggers a null pointer dereference.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - firebird
  - denial-of-service
  - cve-2026-28212
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
  - id: CVE-2026-28212
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28212
rules:
  - title: Detect Firebird SDL_info Null Pointer Dereference
    description: Detects potential exploitation of CVE-2026-28212 by monitoring for Firebird server crashes after network connections from suspicious sources.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - application
      - firebird
  - title: Detect Malformed Firebird Packets
    description: Detects potentially malicious malformed packets being sent to the Firebird server on port 3050, which could be indicative of CVE-2026-28212 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

Firebird is an open-source relational database management system. A denial-of-service vulnerability exists in Firebird versions prior to 6.0.0, 5.0.4, 4.0.7 and 3.0.14 due to improper handling of `op_slice` network packets. Specifically, the server passes an unprepared structure containing a null pointer to the `SDL_info()` function. An unauthenticated attacker can exploit this vulnerability by sending a specially crafted packet to the server's network port, causing a null pointer dereference and subsequent server crash. This vulnerability, identified as CVE-2026-28212, can disrupt database services, affecting applications reliant on the Firebird database. The vulnerability was patched in versions 6.0.0, 5.0.4, 4.0.7 and 3.0.14.

## Attack Chain

1.  Attacker identifies a vulnerable Firebird server running a version prior to 6.0.0, 5.0.4, 4.0.7 or 3.0.14.
2.  Attacker crafts a malicious `op_slice` network packet specifically designed to trigger the vulnerability.
3.  Attacker establishes a network connection to the Firebird server's port (typically 3050).
4.  Attacker sends the crafted `op_slice` packet to the Firebird server.
5.  The server processes the malicious packet, passing an unprepared structure with a null pointer to the `SDL_info()` function.
6.  The `SDL_info()` function attempts to dereference the null pointer.
7.  A null pointer dereference occurs, leading to a server crash.
8.  The Firebird database server becomes unavailable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-28212 results in a denial-of-service condition, rendering the Firebird database server unavailable. This can disrupt applications and services that rely on the database, leading to data unavailability and potential business interruption. While the vulnerability itself does not lead to data compromise, the loss of availability can have significant operational and financial consequences. This issue affects versions of Firebird prior to 6.0.0, 5.0.4, 4.0.7, and 3.0.14.

## Recommendation

*   Upgrade Firebird database servers to version 6.0.0, 5.0.4, 4.0.7 or 3.0.14 or later to patch CVE-2026-28212.
*   Deploy the Sigma rule `Detect Firebird SDL_info Null Pointer Dereference` to identify potential exploitation attempts by detecting network connections followed by server crashes.
*   Monitor network traffic to Firebird servers for unusual or malformed packets using the `Detect Malformed Firebird Packets` Sigma rule, particularly focusing on packets directed to port 3050.
