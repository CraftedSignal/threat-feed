---
title: 'CVE-2026-91149: Denial of Service via Resource Exhaustion in Cockpit'
slug: 2026-09-cockpit-dos
description: An unauthenticated remote attacker can exploit CVE-2026-91149 in Cockpit by exhausting system resources through numerous simultaneous connections to the cockpit-tls service.
date: "2026-09-18T18:08:49Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:cockpit-project:cockpit:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
vendors:
  - Cockpit Project
products:
  - cockpit
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can exploit this vulnerability by initiating and sustaining numerous simultaneous connections to the cockpit-tls service.
    confidence_band: high
cves:
  - id: CVE-2026-91149
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91149
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review system logs for high volumes of connections to Cockpit ports.
      owner: SOC
      due: 48h
      evidence: Source describes exploitation via numerous simultaneous connections.
  mitigation_plan:
    - priority: immediate
      action: Implement rate limiting on the cockpit-tls service using firewall or proxy controls.
      owner: IT Operations
      addresses: CVE-2026-91149
      evidence: Exploit requires sustaining numerous simultaneous connections.
---

A vulnerability identified as CVE-2026-91149 exists in the Cockpit server management software, specifically within the cockpit-tls component. The flaw allows an unauthenticated, remote attacker to trigger a denial of service (DoS) condition. By initiating and sustaining a large volume of simultaneous connections to the cockpit-tls service, an attacker forces the application to spawn an unbounded number of detached threads. This process consumes excessive system resources, including memory and file descriptors, which eventually leads to the degradation or complete unavailability of the Cockpit service for legitimate users. Defenders should monitor for anomalous connection patterns directed at the Cockpit TLS port and evaluate infrastructure resilience against resource exhaustion attacks.

## Impact

Successful exploitation results in the unavailability of the Cockpit interface, impacting system administrators' ability to perform server management tasks. While the attack is limited to a service-level denial of service, the widespread use of Cockpit across enterprise Linux environments makes this a significant availability risk.

## Recommendation

Prioritize monitoring of the cockpit-tls service for abnormal connection counts and duration. Work with IT operations to ensure system resource limits are configured to mitigate the impact of thread-exhaustion events on the host OS.
