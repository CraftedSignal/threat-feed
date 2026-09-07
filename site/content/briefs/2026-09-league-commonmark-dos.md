---
title: Denial of Service Vulnerability in league/commonmark
slug: 2026-09-league-commonmark-dos
description: The league/commonmark library is susceptible to a denial of service attack via crafted Markdown input that triggers quadratic CPU complexity in slug normalization.
date: "2026-09-07T15:33:23Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:league:commonmark:*:*:*:*:*:*:*:*
vendors:
  - league
products:
  - commonmark (>= 2.0.0, < 2.8.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can force many headings onto a single base slug in a small Markdown document, consuming excessive CPU and denying service.
    confidence_band: high
cves:
  - id: CVE-2026-86434
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86434
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade league/commonmark to 2.9.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-86434 mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 2.9.0 or later
      owner: IT Operations
      addresses: CVE-2026-86434
      evidence: NVD advisory
---

The league/commonmark library, versions 2.0.0 through 2.8.3, contains a denial of service (DoS) vulnerability in the UniqueSlugNormalizer::normalize() function. The issue arises when an application enables specific extensions, namely HeadingPermalinkExtension, FootnoteExtension, or TableOfContentsExtension. The vulnerability occurs because the normalization logic resets its numeric-suffix search from 1 every time a slug collision is detected, leading to O(K^2) time complexity relative to the number of headings (K) that resolve to the same base slug. An unauthenticated attacker can supply a small, crafted Markdown document containing a high volume of headings that collapse into a single base slug (such as empty ATX headings or punctuation-only strings). This consumes excessive CPU resources on the server during the parsing phase, resulting in service unavailability. The vulnerability is addressed in version 2.9.0.

## Impact

Successful exploitation allows an unauthenticated remote attacker to cause a denial of service on any application utilizing a vulnerable version of the library with the specified extensions enabled. By forcing significant CPU usage, attackers can degrade or completely halt web application services that process user-supplied Markdown content, impacting sites ranging from documentation platforms to content management systems.

## Recommendation

1. Upgrade league/commonmark to version 2.9.0 or later immediately to resolve CVE-2026-86434.
2. Audit applications utilizing the library to identify those that have HeadingPermalinkExtension, FootnoteExtension, or TableOfContentsExtension enabled.
3. Implement input validation or size limits on user-supplied Markdown content to mitigate the potential for high-volume heading attacks if immediate patching is not feasible.
