---
brief_id: brief-2026-10-31-starlet-perl-vulnerabilities
event_id: brief-2026-10-31-starlet-perl-vulnerabilities
revision: 1
activity_at: "2026-10-31T09:42:57Z"
title: 'Starlet: Multiple vulnerabilities leading to denial of service (CVE-2026-115865, CVE-2026-115866, CVE-2026-116127)'
slug: 2026-10-starlet-perl-vulnerabilities
description: Starlet Perl server versions before 0.33 are vulnerable to memory and CPU exhaustion attacks, alongside response protocol corruption, caused by improper handling of HTTP requests.
date: "2026-10-31T09:42:57Z"
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
  validation_status: Source confirmed; mitigation requires vendor update.
tags:
  - denial-of-service
  - web-server
  - perl
  - cve-2026-115865
  - cve-2026-115866
  - cve-2026-116127
products:
  - Starlet (< 0.33)
cves:
  - id: CVE-2026-115865
    kev_status: "false"
  - id: CVE-2026-115866
    kev_status: "false"
  - id: CVE-2026-116127
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/449
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Starlet to version 0.33 or later
      owner: IT Operations
      due: 48h
      evidence: Starlet versions before 0.33 for Perl allow a request declaring a large Content-Length to kill a worker by exhausting memory
  hunt_leads:
    - lead: Identify high-frequency workers restarts or memory limit alerts for Perl-based web applications
      data_needed:
        - Process management logs or resource monitoring telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Starlet versions before 0.33 for Perl allow a request declaring a large Content-Length to kill a worker by exhausting memory
  mitigation_plan:
    - priority: immediate
      action: Configure ingress proxy/load balancer to reject requests with excessively large Content-Length headers or unusual chunked encoding patterns
      owner: IT Operations
      addresses: CVE-2026-115865, CVE-2026-115866
      evidence: Starlet versions from 0.20 before 0.33 for Perl allow CPU exhaustion via regular expression backtracking when decoding chunked request bodies
---

Starlet versions before 0.33 are affected by multiple vulnerabilities that can result in service disruption. CVE-2026-115865 allows for worker process memory exhaustion via specially crafted Content-Length headers. CVE-2026-115866 permits CPU exhaustion through regular expression backtracking during the decoding of chunked request bodies. Additionally, CVE-2026-116127 causes protocol corruption by incorrectly including bodies in responses to HEAD requests, which may affect subsequent request processing on persistent connections.

## Impact

Successful exploitation of these vulnerabilities can lead to a denial of service (DoS) for the application hosting Starlet. Improper response handling for HEAD requests may lead to data corruption or desynchronization issues in proxy or load balancing environments.

## Recommendation

- Upgrade Starlet to version 0.33 or later immediately.
- Audit existing infrastructure to identify instances of Starlet used in Perl-based web services.
- Implement request header size limits and body processing timeouts at the web server or load balancer layer as a temporary mitigation until services can be patched.
