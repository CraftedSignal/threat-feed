---
brief_id: brief-2026-11-10-flightctl-dos
event_id: brief-2026-11-10-flightctl-dos
revision: 1
activity_at: "2026-11-10T16:38:57Z"
title: 'flightctl: Denial of Service via synchronous TLS handshake (CVE-2026-120399)'
slug: 2026-11-flightctl-dos
description: A vulnerability in flightctl allows an unauthenticated, network-reachable attacker to cause a denial-of-service by stalling the TLS handshake process due to a lack of deadlines in the connection-context callback.
date: "2026-11-10T16:38:57Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: All claims derived from NVD source; vulnerability is currently not stated as exploited.
cpes:
  - cpe:2.3:a:flightctl:flightctl:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - cve-2026-120399
  - network-security
vendors:
  - flightctl
products:
  - flightctl
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A network-reachable unauthenticated client can stall the handshake and prevent the affected listener from accepting new connections.
    confidence_band: high
cves:
  - id: CVE-2026-120399
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120399
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  hunt_leads:
    - lead: Identify abnormal accumulation of long-lived, incomplete TCP or TLS connections to flightctl ports.
      technique_id: T1498
      data_needed:
        - Network firewall or load balancer connection state logs
        - Server-side application connection metrics
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated attacker can consume connection resources, preventing the listener from accepting new connections.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to flightctl interfaces to trusted networks only.
      owner: IT Operations
      addresses: CVE-2026-120399
      evidence: Vulnerability is exploitable by network-reachable, unauthenticated clients.
---

A vulnerability (CVE-2026-120399) exists in flightctl where the HTTP server performs TLS handshakes synchronously within the connection-context callback. Because this process lacks a defined deadline, an unauthenticated, network-reachable attacker can initiate and intentionally stall the handshake. This exhaustion of connection slots prevents the listener from accepting new, legitimate connections, resulting in a denial-of-service condition.

## Impact
The vulnerability results in a denial-of-service, preventing affected flightctl services from accepting new connections from legitimate clients. The CVSS v3.1 base score is 7.5.

## Recommendation
- Audit infrastructure to identify all network-exposed flightctl instances.
- Monitor for increased volumes of incomplete or stalled TLS handshakes originating from external or untrusted network segments.
- Prioritize the application of vendor-provided patches once available to address the lack of connection timeouts.
