---
title: Quadratic-time Denial of Service in league/commonmark
slug: 2026-08-commonmark-dos
description: The league/commonmark library is susceptible to a denial of service vulnerability via crafted Markdown inputs that cause excessive CPU usage and resource exhaustion due to inefficient multibyte character processing.
date: "2026-08-06T21:29:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - commonmark
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker who can submit Markdown for conversion can use a comparatively small request to consume disproportionate CPU time and allocation activity.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2q4p-g7hv-5rgv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71488
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit applications utilizing league/commonmark and schedule upgrades to version 2.9.0+
      owner: Application Security
      due: 72h
      evidence: The issue is patched in 2.9.0 and later.
  mitigation_plan:
    - priority: immediate
      action: Implement length-based input validation for Markdown fields
      owner: IT Operations
      addresses: CVE-2026-71488
      evidence: Reject or truncate inputs with excessively long individual lines before passing them to the converter.
---

The league/commonmark library, a popular PHP Markdown parser, is vulnerable to a denial of service (DoS) flaw (CVE-2026-71488) due to quadratic time complexity during the parsing of specifically crafted Markdown lines. The library improperly handles the translation between character positions and byte positions when processing UTF-8 multibyte characters. By including a single non-ASCII character in a long line containing repeated punctuation or whitespace, an attacker triggers a rescan of the growing string, forcing the parser into an increasingly inefficient state. 

Furthermore, the Autolink extension exhibits similar performance degradation by repeatedly copying and validating the remaining line for every URL-like prefix identified. This vulnerability affects versions 0.6.0 through 2.8.3, including standard `CommonMarkConverter` and `GithubFlavoredMarkdownConverter` instances. An attacker submitting maliciously crafted Markdown to a web application can consume disproportionate CPU and memory resources, leading to the exhaustion of PHP workers and service-wide denial of service. The vulnerability is limited to availability and does not permit data disclosure or unauthorized execution.

## Impact

Successful exploitation results in service unavailability by saturating PHP worker processes. Because the computationally expensive work occurs before HTML rendering, existing security configurations like `html_input` settings do not mitigate the issue. Applications processing untrusted Markdown from public users are at high risk. The complexity of the attack is low, as a single request containing a long, crafted line is sufficient to trigger the resource exhaustion, and no complex Markdown structure is required.

## Recommendation

Prioritized, concrete actions for detection engineering and development teams:
- Upgrade `league/commonmark` to version 2.9.0 or later immediately to resolve the underlying algorithmic flaw in character-to-byte position conversion.
- Implement strict input validation to truncate or reject individual Markdown lines that exceed reasonable length limits before passing them to the parser.
- Configure application-level request limits and rate limiting to prevent concurrent abuse of the parsing engine.
- Apply PHP execution-time limits to ensure individual process requests cannot hang indefinitely during expensive parsing operations.
