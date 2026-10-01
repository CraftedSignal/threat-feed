---
title: Unauthenticated Denial of Service in Podgrab via WebSocket Data Race
slug: 2026-10-podgrab-dos
description: Podgrab is vulnerable to an unauthenticated denial-of-service attack where an attacker can trigger a Go runtime crash by exploiting unsynchronized concurrent access to shared maps in the WebSocket handler.
date: "2026-10-01T20:23:51Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:podgrab:podgrab:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
vendors:
  - Podgrab
products:
  - Podgrab
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote attacker can open multiple WebSocket connections to the /ws endpoint and send messages in a loop to trigger a Go runtime data race that crashes the process.
    confidence_band: high
cves:
  - id: CVE-2026-104057
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104057
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Implement rate limiting on the /ws endpoint at the reverse proxy level to prevent excessive WebSocket message flooding.
      owner: IT Operations
      due: 24h
      evidence: Source describes exploitation via sending messages in a loop to trigger a process crash.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Podgrab to the latest patched version when available.
      owner: IT Operations
      addresses: CVE-2026-104057
      evidence: NVD vulnerability entry documenting the flaw.
---

Podgrab contains a high-severity denial-of-service vulnerability (CVE-2026-104057) originating from unsynchronized concurrent access to shared memory maps. Specifically, the 'activePlayers' and 'allConnections' maps within the application's WebSocket handler are accessed simultaneously by 'Wshandler' and 'HandleWebsocketMessages' goroutines without the use of a mutex or other synchronization primitives. Because the Go runtime panics when concurrent read and write operations are detected on maps, a remote attacker can intentionally trigger this condition. By opening multiple WebSocket connections to the /ws endpoint and flooding the service with messages in a loop, an attacker forces a data race that crashes the entire Podgrab process. The resulting crash requires manual operator intervention to restart the service, making this a persistent denial-of-service condition for exposed instances.

## Impact

The vulnerability allows an unauthenticated remote attacker to crash Podgrab instances, leading to a complete denial of service. The impact is significant for users relying on Podgrab for media management, as the service becomes unavailable until a manual restart occurs. There is no information currently regarding victim count, but any internet-facing Podgrab instance is at risk of disruption.

## Recommendation

Prioritized actions for administrators and detection engineers:
- Monitor webserver logs for anomalous high-frequency WebSocket traffic originating from a single source to the /ws endpoint.
- Patch Podgrab immediately upon the release of a security update that implements proper mutex locking for the 'activePlayers' and 'allConnections' maps.
- Implement rate limiting or connection limits on the /ws endpoint at the reverse proxy or firewall level to mitigate the ease of triggering the crash until a patch is applied.
