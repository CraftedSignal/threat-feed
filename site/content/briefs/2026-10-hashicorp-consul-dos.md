---
brief_id: brief-2026-10-26-hashicorp-consul-dos
event_id: brief-2026-10-26-hashicorp-consul-dos
revision: 1
activity_at: "2026-10-26T19:45:10Z"
title: 'HashiCorp Consul: HTTP API denial of service (CVE-2026-105626)'
slug: 2026-10-hashicorp-consul-dos
description: An unauthenticated denial of service vulnerability in the HashiCorp Consul HTTP API allows remote attackers to exhaust memory on target agents, leading to service unavailability.
date: "2026-10-26T19:45:10Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch requirements sourced directly from NVD; environment-specific testing of API ACLs required.
cpes:
  - cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*
  - cpe:2.3:a:hashicorp:consul_enterprise:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - hashicorp
  - vulnerability
vendors:
  - HashiCorp
products:
  - Consul Community Edition (< 2.1.0)
  - Consul Enterprise (< 2.1.0, < 1.21.19)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: An unauthenticated attacker can exploit this flaw to cause memory exhaustion on a Consul agent, leading to a crash or service unavailability.
    confidence_band: high
cves:
  - id: CVE-2026-105626
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105626
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Consul Community Edition to 2.1.0 and Consul Enterprise to 2.1.0 or 1.21.19
      owner: IT Operations
      due: 48h
      evidence: Vulnerability is fixed in Consul Community Edition 2.1.0 and Consul Enterprise 2.1.0 and 1.21.19.
  hunt_leads:
    - lead: Monitor for spikes in agent memory usage or service crashes associated with high volumes of HTTP API traffic
      technique_id: T1499
      data_needed:
        - Consul agent log files (process termination events)
        - System metrics (memory usage per process)
        - Web server / API gateway access logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: Unauthenticated attacker can exhaust memory on a Consul agent.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Consul HTTP API endpoints to trusted management CIDRs
      owner: Security Engineering
      addresses: CVE-2026-105626
      evidence: Vulnerability in HTTP API allows unauthenticated attacker exploitation.
---

HashiCorp Consul and Consul Enterprise contain a denial of service (DoS) vulnerability in the HTTP API. An unauthenticated attacker can send crafted requests to the HTTP API, leading to uncontrolled memory exhaustion on the Consul agent process. This impacts both the Community and Enterprise editions of the product. The vulnerability is assigned CVE-2026-105626 with a CVSS v3.1 base score of 7.5.

## Impact

Successful exploitation results in memory exhaustion on the Consul agent, which causes the service to crash or become unresponsive, leading to denial of service for any applications relying on the agent for service discovery or key-value store access.

## Recommendation

* Patch HashiCorp Consul to the following versions immediately:
 * Consul Community Edition: Upgrade to version 2.1.0 or later.
 * Consul Enterprise: Upgrade to version 2.1.0 or version 1.21.19 or later.
* Audit access to the Consul HTTP API. Ensure that the API is not exposed to untrusted networks and utilize ACLs to restrict unauthenticated access to the HTTP endpoint where possible.
