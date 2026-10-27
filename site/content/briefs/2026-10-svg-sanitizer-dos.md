---
brief_id: brief-2026-10-27-svg-sanitizer-dos
event_id: brief-2026-10-27-svg-sanitizer-dos
revision: 1
activity_at: "2026-10-27T11:47:03Z"
title: 'svg-sanitizer: Denial of service via regex complexity (CVE-2026-117540)'
slug: 2026-10-svg-sanitizer-dos
description: The svg-sanitizer library, versions 0.5.3 through 1.0.x, contains a denial-of-service vulnerability in the Sanitizer::sanitize method that allows unauthenticated attackers to exhaust CPU resources via crafted SVG files.
date: "2026-10-27T11:47:03Z"
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
  validation_status: Source-verified vulnerability details
cpes:
  - cpe:2.3:a:svg-sanitizer:svg-sanitizer:*:*:*:*:*:*:*:*
products:
  - svg-sanitizer (>= 0.5.3, < 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can upload SVGs with many overlapping PHP tag openers and closers, forcing quadratic preg_replace passes that exhaust worker CPU for minutes.
    confidence_band: high
cves:
  - id: CVE-2026-117540
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117540
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade svg-sanitizer library to version 1.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-117540 fix addressed in version 1.1.0
  hunt_leads:
    - lead: Identify and analyze application logs for abnormal PHP processing duration or excessive CPU usage spikes linked to SVG upload endpoints.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application performance monitoring (APM) logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability leads to prolonged CPU usage during Sanitizer::sanitize execution.
  mitigation_plan:
    - priority: immediate
      action: Implement request size limits and validation for file uploads to mitigate potential DoS vectors
      owner: IT Operations
      addresses: CVE-2026-117540
      evidence: Crafted SVGs with many overlapping tags are used to trigger excessive CPU usage
---

A denial of service vulnerability exists in the svg-sanitizer library (versions 0.5.3 up to 1.1.0). The Sanitizer::sanitize() method performs inefficient regex processing when stripping PHP tags from input. By providing a specially crafted SVG file containing a high density of overlapping PHP tag openers and closers, an attacker can trigger quadratic complexity in the preg_replace function. This results in prolonged CPU usage, potentially leading to service exhaustion for applications relying on the library for SVG processing.

## Impact
Successful exploitation allows unauthenticated attackers to trigger sustained, high CPU utilization on the server processing the SVG input, leading to service disruption or denial of service.

## Recommendation
Upgrade the svg-sanitizer library to version 1.1.0 or later immediately to incorporate the fix for regex complexity. If immediate patching is not possible, implement strict file size and complexity limits for uploaded SVG files as an interim mitigation.
