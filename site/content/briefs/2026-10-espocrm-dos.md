---
brief_id: brief-2026-10-28-espocrm-dos
event_id: brief-2026-10-28-espocrm-dos
revision: 1
activity_at: "2026-10-28T20:39:06Z"
title: 'EspoCRM: Denial of service via ReDoS (CVE-2026-118686)'
slug: 2026-10-espocrm-dos
description: EspoCRM versions before 9.3.11 and 10.x before 10.0.8 are vulnerable to a denial of service attack where an unauthenticated attacker can exhaust server resources by submitting large API requests that trigger a vulnerable password-redaction regex.
date: "2026-10-28T20:39:06Z"
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
  validation_status: verified against NVD advisory content
cpes:
  - cpe:2.3:a:espocrm:espocrm:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-application
  - redos
  - cve-2026-118686
vendors:
  - EspoCRM
products:
  - EspoCRM (< 9.3.11)
  - EspoCRM (10.x < 10.0.8)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: Unauthenticated remote attackers can concurrently send a small number of large API requests to exhaust server workers, making EspoCRM slow or unavailable to legitimate users.
    confidence_band: high
cves:
  - id: CVE-2026-118686
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118686
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade EspoCRM to version 9.3.11 or 10.0.8
      owner: IT Operations
      due: 72h
      evidence: Source advisory specifies affected versions before 9.3.11 and 10.x before 10.0.8
  hunt_leads:
    - lead: Identify abnormal API request volume or size
      technique_id: T1499.001
      data_needed:
        - Web server access logs containing request body size and processing latency
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated remote attackers can concurrently send a small number of large API requests
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Load Balancer to reject requests with excessively large bodies
      owner: IT Operations
      addresses: CVE-2026-118686
      evidence: Exploit requires sending large API requests
---

EspoCRM contains a denial of service vulnerability identified as CVE-2026-118686. The issue resides in the password-redaction regular expression used during API error handling. An unauthenticated remote attacker can exploit this by sending a small number of concurrent, abnormally large API requests. These requests force the application to perform expensive regex operations, leading to high CPU usage, worker exhaustion, and potential service unavailability for legitimate users.

## Impact

Successful exploitation results in a denial of service state, where the application becomes slow or completely unresponsive due to exhausted server worker processes.

## Recommendation

- Upgrade EspoCRM to version 9.3.11 or 10.0.8 or later to incorporate the patch for the vulnerable password-redaction logic.
- Implement request body size limits at the load balancer or web application firewall (WAF) level to prevent the processing of abnormally large API payloads.
- Audit web server access logs for repeated requests to API endpoints that result in long processing times or HTTP 500/503 errors indicative of worker exhaustion.
