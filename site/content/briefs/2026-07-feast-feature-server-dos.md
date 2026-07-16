---
title: Feast Feature Server Denial of Service via Unauthenticated WebSocket Connections (CVE-2026-23538)
slug: 2026-07-feast-feature-server-dos
description: A vulnerability (CVE-2026-23538) exists in the Feast Feature Server's /ws/chat endpoint, allowing remote attackers to establish numerous unauthenticated, persistent WebSocket connections. This exploit, a form of resource exhaustion (CWE-770), consumes server resources like memory, CPU, and file descriptors, leading to a complete denial of service for legitimate users. Affected versions are those prior to 0.59.0.
date: "2026-07-16T01:18:43Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - websocket
  - resource-exhaustion
  - feast-feature-server
vendors:
  - Feast
  - Red Hat
products:
  - Feast Feature Server (<= 0.58.0)
  - Red Hat OpenShift AI
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: By opening a large number of simultaneous connections, an attacker can exhaust server resources—such as memory, CPU, and file descriptors—leading to a complete denial of service for legitimate users.
    confidence_band: high
cves:
  - id: CVE-2026-23538
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23538
  - https://access.redhat.com/security/cve/CVE-2026-23538
  - https://bugzilla.redhat.com/show_bug.cgi?id=2429311
  - https://github.com/red-hat-data-services/feast/pull/192
rules:
  - title: Detect Unauthenticated WebSocket Connection Attempts to Feast Feature Server '/ws/chat' Endpoint
    description: Detects attempts to establish unauthenticated WebSocket connections to the Feast Feature Server's vulnerable /ws/chat endpoint (CVE-2026-23538). A high volume of such connections may indicate a denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, identified as CVE-2026-23538, has been discovered in the Feast Feature Server's `/ws/chat` endpoint. This flaw allows remote, unauthenticated attackers to establish a high volume of persistent WebSocket connections. By repeatedly exploiting this unauthenticated access, attackers can exhaust vital server resources, including memory, CPU, and file descriptors. This resource depletion can lead to a complete denial of service (DoS) for legitimate users attempting to access the Feast Feature Server. The vulnerability affects Feast Feature Server versions prior to 0.59.0 and is categorized as a resource exhaustion issue (CWE-770). Red Hat has acknowledged this vulnerability, indicating its potential impact on deployments leveraging Red Hat OpenShift AI (RHOAI) which may include affected Feast components. This issue poses a significant threat to the availability and stability of services relying on vulnerable Feast Feature Server instances.

## Attack Chain

1. An attacker identifies a publicly accessible instance of the Feast Feature Server running a vulnerable version (prior to 0.59.0).
2. The attacker initiates a large number of unauthenticated WebSocket handshake requests targeting the `/ws/chat` endpoint on the vulnerable server.
3. The Feast Feature Server, due to the vulnerability, establishes and maintains these persistent WebSocket connections without requiring any form of authentication.
4. The continuous establishment and maintenance of numerous unauthenticated connections rapidly consume the server's available resources, such as memory and CPU cycles.
5. The server also exhausts its capacity for file descriptors, which are required for each open connection.
6. As critical resources become depleted, the Feast Feature Server becomes unresponsive to legitimate requests, resulting in a complete denial of service.

## Impact

Successful exploitation of CVE-2026-23538 leads to a complete denial of service for the Feast Feature Server. This means legitimate users will be unable to access feature data, disrupting critical applications and services that rely on the server. The attack exhausts server resources such as memory, CPU, and file descriptors, rendering the server inoperable. While no specific victim numbers or targeted sectors are detailed in the advisory, any organization utilizing vulnerable versions of the Feast Feature Server, especially those integrated into platforms like Red Hat OpenShift AI, is at risk of severe operational disruption and potential data pipeline failures.

## Recommendation

* Patch CVE-2026-23538 immediately by upgrading Feast Feature Server to version 0.59.0 or later to mitigate the vulnerability.
* Deploy the Sigma rule "Detect Unauthenticated WebSocket Connection Attempts to Feast Feature Server '/ws/chat' Endpoint" to your SIEM and investigate any alerts, especially in conjunction with unusually high connection rates or resource utilization on Feast servers.
* Implement network-level rate limiting or connection throttling for ingress traffic targeting the Feast Feature Server's `/ws/chat` endpoint to prevent resource exhaustion attacks.
* Monitor `webserver` logs for a high volume of connections to `/ws/chat` from single or multiple IP addresses, particularly without expected authentication headers.
