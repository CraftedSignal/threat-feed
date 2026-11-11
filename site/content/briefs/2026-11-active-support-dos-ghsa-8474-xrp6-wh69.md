---
brief_id: brief-2026-11-11-active-support-dos-ghsa-8474-xrp6-wh69
event_id: brief-2026-11-11-active-support-dos-ghsa-8474-xrp6-wh69
revision: 1
activity_at: "2026-11-11T11:52:06Z"
title: 'Active Support: Denial of Service via safe_constantize (CVE-2026-126080)'
slug: 2026-11-active-support-dos-ghsa-8474-xrp6-wh69
description: An unescaped regular expression in Active Support’s safe_constantize method allows unauthenticated remote attackers to trigger a server process crash via Action Cable, resulting in a Denial of Service.
date: "2026-11-11T11:52:06Z"
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
  - cpe:2.3:a:rubyonrails:activesupport:*:*:*:*:*:ruby:*:*
vendors:
  - Ruby on Rails
products:
  - Active Support (< 8.0.5.2)
  - Active Support (>= 8.1, < 8.1.4.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Crafted patterns can trigger defects in Ruby regular expression compiler, possibly leading to a crash of the server process, and repeated requests could keep the application unavailable.
    confidence_band: high
cves:
  - id: CVE-2026-126080
    cvss: 7.5
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-8474-xrp6-wh69
  - https://github.com/rails/rails/commit/95aa9e416016524956d4904fed96eaed079580bb
  - https://github.com/rails/rails/commit/210ac22d446c8e2625b091e79256806b836eee20
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade activesupport to 8.0.5.2 or 8.1.4.1
      owner: IT Operations
      due: 48h
      evidence: Fixed releases address the regular expression compilation defect
  hunt_leads:
    - lead: Identify high-frequency 500-series errors or sudden process restarts originating from the /cable endpoint
      technique_id: T1499
      data_needed:
        - Web server access logs
        - Application server error logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Action Cable passes the channel value of each subscribe command to safe_constantize, making it reachable via the endpoint.
  mitigation_plan:
    - priority: immediate
      action: Implement reject_unauthorized_connection in ActionCable::Connection#connect
      owner: IT Operations
      addresses: CVE-2026-126080
      evidence: Limits exposure to unauthenticated remote attackers
---

Active Support's `safe_constantize` method contains a vulnerability where untrusted input passed into constant lookup can trigger a server-side crash due to unescaped regular expression compilation when a `LoadError` occurs. In default Rails configurations, the Action Cable endpoint passes unsanitized input to this method, allowing unauthenticated remote attackers to trigger a Denial of Service by causing the application process to crash.

## Impact
Crafted inputs to `safe_constantize` can exploit defects in Ruby's regular expression compiler, causing the server process to crash. Repeated requests lead to sustained application unavailability.

## Recommendation
- Upgrade `activesupport` to version 8.0.5.2 or 8.1.4.1 to include the patched logic that uses literal string matching.
- For applications that do not require Action Cable, set `config.action_cable.mount_path = nil` to disable the vulnerable endpoint.
- For applications utilizing Action Cable, implement `reject_unauthorized_connection` within `ApplicationCable::Connection#connect` to restrict access to authenticated users.
