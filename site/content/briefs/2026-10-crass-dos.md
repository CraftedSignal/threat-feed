---
brief_id: brief-2026-10-crass-dos
event_id: brief-2026-10-crass-dos
revision: 1
activity_at: "2026-10-20T14:43:22Z"
title: 'Crass: Denial of service via CSS exponentiation (CVE-2026-61845)'
slug: 2026-10-crass-dos
description: The Crass Ruby gem is vulnerable to a denial of service condition where maliciously crafted CSS numeric exponents trigger excessive CPU and memory consumption.
date: "2026-10-20T14:43:22Z"
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
cpes:
  - cpe:2.3:a:crass_project:crass:*:*:*:*:*:ruby:*:*
tags:
  - denial-of-service
  - ruby
  - css
vendors:
  - RubyGems
products:
  - crass (< 1.0.7)
cves:
  - id: CVE-2026-61845
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-6wmf-3r64-vcwv
  - https://github.com/rubysec/ruby-advisory-db/blob/master/gems/crass/GHSA-6wmf-3r64-vcwv.yml
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade cras gem to 1.0.7
      owner: IT Operations
      due: 48h
      evidence: This is fixed in Crass 1.0.7.
---

The Crass Ruby gem (versions prior to 1.0.7) is susceptible to a denial of service (DoS) vulnerability, identified as CVE-2026-61845. The library fails to properly validate or limit numeric exponents found in CSS strings during parsing. When an application processes attacker-controlled CSS, an attacker can submit a string containing an extremely large numeric exponent. The library attempts to calculate the result of this exponentiation before clamping it to the maximum float value, leading to disproportionate CPU and memory consumption. This resource exhaustion can result in application instability or process crashes, impacting any service that relies on Crass for sanitizing or parsing user-supplied CSS.

## Impact

The vulnerability allows remote attackers to cause a denial of service on applications using the Crass library to process untrusted CSS content. Successful exploitation leads to excessive resource consumption and application crashes, potentially disrupting availability for all users of the affected service. The vulnerability affects all users of Crass versions below 1.0.7 in any sector utilizing this Ruby gem.

## Recommendation

1. Upgrade the Crass gem to version 1.0.7 or later to implement proper clamping of numeric exponents.
2. Implement input validation and length limits for all user-supplied CSS before passing the content to the Crass parser.
3. Monitor application error logs for memory exhaustion or process restarts occurring during CSS parsing operations.
