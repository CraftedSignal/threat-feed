---
title: Fleet Server gRPC PublishLogs Endpoint Denial-of-Service Vulnerability (CVE-2026-26062)
slug: 2026-05-fleet-grpc-dos
description: Fleet server versions prior to 4.81.0 are vulnerable to a denial-of-service (DoS) via the gRPC Launcher `PublishLogs` endpoint, where unexpected input values can cause the server process to terminate upon receiving a crafted request from an authenticated Launcher host.
date: "2026-05-14T13:18:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - grpc
  - fleet
  - github advisory
vendors:
  - FleetDM
products:
  - fleet/v4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-x67p-9m2r-fxqv
  - CVE-2026-26062
iocs:
  - type: email
    value: security@fleetdm.com
ioc_counts:
  email: 1
rules:
  - title: Detect Fleet Server Crashes
    description: Detects unexpected Fleet server process termination, which could indicate exploitation of CVE-2026-26062 or other issues.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect gRPC requests to PublishLogs endpoint
    description: Detects network connections to the PublishLogs endpoint of Fleet gRPC server. Reviewing this activity can help detect attempts to exploit CVE-2026-26062.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Fleet server versions before 4.81.0 contain a denial-of-service vulnerability affecting the gRPC Launcher's `PublishLogs` endpoint. This flaw allows an authenticated attacker, possessing a valid Launcher node key, to send a specially crafted gRPC request that the Fleet server fails to handle gracefully. The unexpected input within this request triggers a condition leading to the immediate termination of the Fleet server process, causing a complete denial of service. The vulnerability, assigned CVE-2026-26062, stems from inadequate input validation on the `PublishLogs` endpoint. Successful exploitation requires a valid Launcher node key, limiting the attack surface to compromised or malicious Launcher hosts enrolled within the Fleet management infrastructure.

## Attack Chain

1. Attacker gains access to a valid Launcher node key, either through compromise of a Launcher host or insider threat.
2. Attacker crafts a malicious gRPC request specifically targeting the `PublishLogs` endpoint of the Fleet server.
3. The malicious gRPC request contains unexpected or malformed input designed to trigger the vulnerability.
4. Attacker authenticates to the Fleet server using the compromised Launcher node key.
5. Attacker sends the crafted gRPC request to the `PublishLogs` endpoint.
6. The Fleet server receives the malicious request and attempts to process the malformed input.
7. Due to inadequate input validation, the server encounters an unhandled exception or error condition.
8. The unhandled exception causes the Fleet server process to terminate unexpectedly, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability results in an immediate and complete denial of service, impacting the availability of Fleet server. This could disrupt endpoint monitoring, policy enforcement, and other critical security functions dependent on the Fleet platform. Although there is no exposure of sensitive data, authentication bypass, privilege escalation, or integrity impact, the disruption to operations can be significant, especially in environments relying heavily on Fleet for endpoint management and security visibility. The number of affected organizations depends on the prevalence of Fleet deployments and the attacker's ability to compromise Launcher node keys.

## Recommendation

*   Upgrade Fleet server to version 4.81.0 or later to remediate the vulnerability (CVE-2026-26062).
*   Restrict network access to the Fleet gRPC endpoint (where feasible) to limit potential attack surfaces, as described in the advisory.
*   Deploy Fleet behind infrastructure that terminates or filters gRPC traffic if Launcher log ingestion is not required, mitigating the impact of malicious requests.
*   Monitor for repeated Fleet process crashes or unexpected restarts, indicating potential exploitation attempts, as suggested in the advisory.
*   Implement the Sigma rule "Detect Fleet Server Crashes" to identify potential exploitation attempts based on server crash events.
