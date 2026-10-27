---
brief_id: brief-2026-10-27-starman-dos
event_id: brief-2026-10-27-starman-dos
revision: 1
activity_at: "2026-10-27T00:32:53Z"
title: 'Starman: Multiple denial-of-service vulnerabilities (CVE-2026-115817, CVE-2026-115822, CVE-2026-115823)'
slug: 2026-10-starman-dos
description: Starman versions prior to 0.4019 are susceptible to multiple denial-of-service vectors, including resource exhaustion via stalled request bodies, CPU exhaustion from regex backtracking, and response desynchronization.
date: "2026-10-27T00:32:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - denial-of-service
  - webserver
  - perl
  - vulnerability
products:
  - Starman (< 0.4019)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Starman versions before 0.4019 for Perl allow a stalled request body to hold a worker indefinitely, as read_timeout covers only the headers
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.002
    technique_name: Service Exhaustion Flood
    evidence: Starman versions before 0.4019 for Perl allow CPU exhaustion via quadratic regex backtracking when parsing chunked request bodies
    confidence_band: high
cves:
  - id: CVE-2026-115817
    kev_status: "false"
  - id: CVE-2026-115822
    kev_status: "false"
  - id: CVE-2026-115823
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/388
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Starman to 0.4019 or later
      owner: IT Operations
      due: 48h
      evidence: Starman versions before 0.4019 are vulnerable
  hunt_leads:
    - lead: Identify endpoints served by Starman processes
      technique_id: T1499
      data_needed:
        - Server asset inventory
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Vulnerabilities impact Starman server infrastructure
  mitigation_plan:
    - priority: immediate
      action: Upgrade Starman Perl module to 0.4019+
      owner: IT Operations
      addresses: CVE-2026-115817, CVE-2026-115822, CVE-2026-115823
      evidence: Starman versions before 0.4019 contain multiple DoS vulnerabilities
---

Starman, a high-performance Perl web server, contains multiple vulnerabilities in versions prior to 0.4019. These flaws enable denial-of-service attacks against the web server infrastructure.

## Impact
The vulnerabilities allow for service instability or total unavailability through resource exhaustion or protocol-level desynchronization. Specifically, attackers can lock up worker processes by stalling request bodies, cause CPU-bound denial of service via regex backtracking, or desynchronize communication by receiving unexpected response bodies for HEAD requests.

## Recommendation
- Upgrade the Starman Perl module to version 0.4019 or later across all environments where the web server is deployed.
- Implement request timeout monitoring and rate limiting at the upstream load balancer or reverse proxy level to mitigate potential exploitation attempts while the patching process is underway.
