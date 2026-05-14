---
title: Synapse CPU Starvation Denial of Service Vulnerability
slug: 2026-05-synapse-cpu-starvation
description: A denial-of-service vulnerability exists in Synapse where local authenticated users can cause CPU starvation, leading to request failures for other users (CVE-2026-45078).
date: "2026-05-14T16:25:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - synapse
  - cpu-starvation
vendors:
  - Element
products:
  - matrix-synapse (< 1.152.1)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-8q93-326v-3m7g
iocs:
  - type: email
    value: security@element.io
ioc_counts:
  email: 1
rules:
  - title: Detect High CPU Usage by Synapse Process
    description: Detects abnormally high CPU usage by the Synapse process, potentially indicating a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Multiple Synapse Processes from the Same User
    description: Detects multiple Synapse processes initiated by the same user, potentially indicative of an attempt to exhaust resources
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A denial-of-service (DoS) vulnerability, identified as CVE-2026-45078, affects Synapse, a Matrix homeserver implementation. Local authenticated users can exploit this vulnerability to starve other requests of CPU resources, causing request failures and denying service to other users. This vulnerability is present in Synapse versions prior to 1.152.1. Homeservers that trust all their local users are not at risk. Element has released Synapse version 1.152.1 to address this issue. Applying rate limiting at a reverse proxy deployed in front of Synapse can mitigate the impact.

## Attack Chain

1. A local, authenticated user logs into the Synapse homeserver.
2. The attacker crafts a series of requests that consume excessive CPU resources on the Synapse server. This could involve complex queries, large data transfers, or computationally intensive operations.
3. The attacker sends these crafted requests to the Synapse server.
4. The Synapse server begins processing the attacker's requests, dedicating significant CPU resources to them.
5. Legitimate user requests arrive at the Synapse server.
6. Due to the CPU resources being consumed by the attacker's requests, legitimate user requests are delayed or dropped.
7. Users experience degraded performance or complete denial of service.
8. The attacker successfully causes a denial of service by exhausting CPU resources, preventing other users from accessing the Synapse homeserver.

## Impact

Successful exploitation of this vulnerability can lead to a denial of service, preventing legitimate users from accessing the Synapse homeserver. The number of affected users depends on the size and activity of the Synapse deployment. Organizations relying on Synapse for critical communication may experience significant disruptions.

## Recommendation

*   Upgrade Synapse to version 1.152.1 or later to patch CVE-2026-45078.
*   If immediate patching is not possible, configure a reverse proxy in front of Synapse to limit the rate of user requests, as suggested in the advisory.
*   Monitor CPU usage on the Synapse server for unusual spikes that may indicate an ongoing attack. Use process accounting logs to identify high-CPU processes.
*   Deploy the Sigma rule "Detect High CPU Usage by Synapse Process" to identify potential DoS attacks.
