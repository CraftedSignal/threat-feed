---
brief_id: brief-2026-11-08-imgproxy-memory-exhaustion
event_id: brief-2026-11-08-imgproxy-memory-exhaustion
revision: 1
activity_at: "2026-11-08T11:21:16Z"
title: 'imgproxy: Unbounded memory allocation in ICO loader (CVE-2026-123616)'
slug: 2026-11-imgproxy-memory-exhaustion
description: An unauthenticated attacker can exploit an unbounded memory allocation vulnerability in the imgproxy ICO loader to trigger process crashes and denial-of-service via malformed file uploads.
date: "2026-11-08T11:21:16Z"
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
cpes:
  - cpe:2.3:a:imgproxy:imgproxy:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - image-processing
  - memory-exhaustion
vendors:
  - imgproxy
products:
  - imgproxy (>= 3.3.0, < 4.0.16)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: OS Exhaustion Flood
    evidence: Attackers can supply a crafted 23-byte ICO file declaring a ~4GB data_size to trigger memory exhaustion and worker crashes.
    confidence_band: high
cves:
  - id: CVE-2026-123616
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123616
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch imgproxy to 4.0.16 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-123616 vendor patch release
  hunt_leads:
    - lead: Identify repeated worker process crashes in application logs
      technique_id: T1499.001
      data_needed:
        - Application logs (stderr/stdout)
        - Orchestrator restart events (e.g., Kubernetes OOMKilled events)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability leads to worker crashes via memory exhaustion
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 4.0.16
      owner: IT Operations
      addresses: CVE-2026-123616
      evidence: NVD advisory for CVE-2026-123616
---

imgproxy versions 3.3.0 through 4.0.15 are affected by an unbounded memory allocation vulnerability (CVE-2026-123616) in the ICO image processing module. The loader fails to validate the `data_size` field in processed ICO files. An attacker can submit a crafted 23-byte ICO file specifying a `data_size` of approximately 4GB, causing the service to allocate excessive memory, leading to worker process exhaustion and crashes.

## Impact
Successful exploitation results in a denial-of-service condition for the imgproxy instance by inducing memory exhaustion and crashing worker processes.

## Recommendation
- Upgrade imgproxy instances to version 4.0.16 or later to include the mandatory validation of the `data_size` field in the ICO loader.
- Implement request body size limits at the load balancer or reverse proxy level (e.g., Nginx `client_max_body_size`) if immediate patching is not feasible, though this will not prevent the specific vulnerability if small-file payloads are allowed.
- Monitor logs for repeated worker process restarts or high memory usage spikes correlated with image processing tasks.
