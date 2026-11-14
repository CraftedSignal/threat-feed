---
brief_id: brief-2026-11-14-automapper-dos-ghsa-gpwp-5797-mjff
event_id: brief-2026-11-14-automapper-dos-ghsa-gpwp-5797-mjff
revision: 1
activity_at: "2026-11-14T02:25:20Z"
title: 'AutoMapper: Denial of service via uncontrolled recursion (CVE-2026-128081)'
slug: 2026-11-automapper-dos-ghsa-gpwp-5797-mjff
description: AutoMapper is vulnerable to a denial of service attack where malicious, deeply nested data triggers an uncatchable StackOverflowException by bypassing MaxDepth constraints.
date: "2026-11-14T02:25:20Z"
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
  validation_status: Reviewed against GHSA-gpwp-5797-mjff
cpes:
  - cpe:2.3:a:automapper:automapper:*:*:*:*:*:*:*:*
vendors:
  - AutoMapper
products:
  - AutoMapper
  - AutoMapper (>= 16.0.0, < 16.3.0)
product_versions:
  - product: AutoMapper
    range: < 15.1.4
cves:
  - id: CVE-2026-128081
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-gpwp-5797-mjff
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Inventory applications utilizing AutoMapper versions < 15.1.4 or 16.0.0-16.2.x.
      owner: IT Operations
      due: 48h
      evidence: Vulnerable version ranges documented in GHSA-gpwp-5797-mjff
  mitigation_plan:
    - priority: immediate
      action: Upgrade AutoMapper to 15.1.4 (for 15.x) or 16.3.0 (for 16.x) or later.
      owner: Development Team
      addresses: CVE-2026-128081
      evidence: GHSA-gpwp-5797-mjff
---

AutoMapper is susceptible to a denial of service vulnerability (CVE-2026-128081) where uncontrolled recursion occurs within specific mapping paths. While previous mitigations introduced MaxDepth limits, those protections do not apply to polymorphic maps, members typed as object or interface, dictionary/dynamic sources, and recursive type converters. An attacker providing deeply nested input can cause the application to trigger a StackOverflowException, which results in process termination.

## Impact

Successful exploitation causes immediate process termination, leading to a denial of service. The impact is significant for applications that map user-supplied or external data using AutoMapper without input depth sanitization.

## Recommendation

Upgrade AutoMapper to a patched release. For environments using the 15.x branch, upgrade to 15.1.4 or later. For environments using the 16.x branch, upgrade to 16.3.0 or later. Where patching is not immediate, perform strict input depth validation before mapping operations to prevent deeply nested structures from reaching the mapper.
