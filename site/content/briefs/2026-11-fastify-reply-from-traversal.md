---
brief_id: brief-2026-11-02-fastify-reply-from-traversal
event_id: brief-2026-11-02-fastify-reply-from-traversal
revision: 1
activity_at: "2026-11-02T11:28:47Z"
title: 'Fastify: @fastify/reply-from path traversal (CVE-2026-117518)'
slug: 2026-11-fastify-reply-from-traversal
description: The @fastify/reply-from plugin contains a path traversal vulnerability where backslash dot-segments allow attackers to bypass proxy prefix constraints, enabling unauthorized access to unintended upstream endpoints.
date: "2026-11-02T11:28:47Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-based assessment complete
cpes:
  - cpe:2.3:a:fastify:reply-from:*:*:*:*:*:*:*:*
vendors:
  - Fastify
products:
  - '@fastify/reply-from (<= 12.8.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that scopes proxying to an upstream prefix, or relies on route guards in front of the forwarding call, can have an unauthenticated request escape the intended prefix and reach other upstream endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-117518
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117518
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade @fastify/reply-from to 12.8.1 or later
      owner: IT Operations
      due: 48h
      evidence: The issue is fixed in @fastify/reply-from 12.8.1
  hunt_leads:
    - lead: Identify access logs showing request paths with backslashes or encoded backslash sequences (%5C) targeting applications that use @fastify/reply-from
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A path that uses backslash dot-segments therefore bypasses the traversal check and resolves to a different upstream path
  mitigation_plan:
    - priority: immediate
      action: Update vulnerable packages to version 12.8.1
      owner: IT Operations
      addresses: CVE-2026-117518
      evidence: The issue is fixed in @fastify/reply-from 12.8.1
---

The @fastify/reply-from plugin (versions up to and including 12.8.0) fails to properly validate proxy paths containing backslash dot-segments. The WHATWG URL parser used by the plugin normalizes these backslashes to forward slashes, bypassing security guards intended to scope proxying to specific upstream prefixes. An attacker can exploit this to access restricted upstream API endpoints. The vulnerability is fixed in version 12.8.1.

## Impact

Successful exploitation allows unauthenticated users to escape intended proxy boundaries, resulting in unauthorized access to unintended upstream resources. This is primarily a confidentiality impact with limited integrity impact.

## Recommendation

Update the @fastify/reply-from package to version 12.8.1 or later. There are no available workarounds.
