---
brief_id: brief-2026-11-06-parse-server-redos
event_id: brief-2026-11-06-parse-server-redos
revision: 1
activity_at: "2026-11-06T17:23:44Z"
title: 'Parse Server: Regular expression denial of service (CVE-2026-123487)'
slug: 2026-11-parse-server-redos
description: Parse Server versions before 8.6.115 and 9.x before 9.10.7-alpha.1 contain a regular expression denial of service (ReDoS) vulnerability that allows unauthenticated or authenticated attackers to exhaust the Node.js event loop via crafted email addresses.
date: "2026-11-06T17:23:44Z"
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
cpes:
  - cpe:2.3:a:parseplatform:parse-server:*:*:*:*:*:*:*:*
vendors:
  - Parse Platform
products:
  - Parse Server (< 8.6.115, 9.0.0 before 9.10.7-alpha.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: An unauthenticated attacker... can send a sign-up request... with a long crafted email address to block the Node.js event loop and deny service to all clients.
    confidence_band: high
cves:
  - id: CVE-2026-123487
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123487
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Parse Server to version 8.6.115 or 9.10.7-alpha.1.
      owner: IT Operations
      due: 48h
      evidence: Parse Server before 8.6.115 and 9.0.0 before 9.10.7-alpha.1 validates user email address format with a regular expression whose run time grows quadratically
  hunt_leads:
    - lead: Identify unusually long email address strings in incoming HTTP POST requests to user registration or update endpoints.
      technique_id: T1499.001
      data_needed:
        - Web server access logs
        - WAF request body inspection logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: an unauthenticated attacker... can send a sign-up request... with a long crafted email address
  mitigation_plan:
    - priority: immediate
      action: Configure WAF/Load Balancer to enforce maximum length limits (e.g., 255 characters) for email address fields in POST payloads.
      owner: IT Operations
      addresses: CVE-2026-123487
      evidence: application does not enforce a length limit on this input
---

Parse Server versions before 8.6.115 and 9.x before 9.10.7-alpha.1 are vulnerable to a regular expression denial of service (ReDoS). The vulnerability stems from a regular expression used for email address validation that exhibits quadratic runtime complexity relative to input length. Because the application does not enforce a length limit on this input, an attacker can submit an excessively long, specially crafted email address to block the Node.js event loop, effectively denying service to all users.

## Impact

The vulnerability allows an unauthenticated or authenticated attacker to cause a denial of service by hanging the Node.js process, which prevents the server from processing further requests. This can be achieved during the account sign-up process or by updating a user profile.

## Recommendation

- Upgrade Parse Server to version 8.6.115 or higher, or 9.10.7-alpha.1 or higher.
- Implement request body size limits and input length validation at the load balancer or web application firewall (WAF) level to mitigate the submission of malformed, oversized email addresses.
- Monitor server performance and process health for spikes in CPU usage associated with POST requests to user account endpoints.
