---
title: Algorithmic Complexity Denial of Service in league/commonmark
slug: 2026-08-league-commonmark-dos
description: A quadratic time complexity vulnerability in the UniqueSlugNormalizer component of league/commonmark 2.x allows attackers to trigger CPU exhaustion via specially crafted Markdown documents.
date: "2026-08-06T21:29:30Z"
lastmod: "2026-08-06T21:29:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - algorithmic-complexity
  - vulnerability
vendors:
  - league
products:
  - commonmark (>= 2.0.0, < 2.9.0)
  - commonmark (>= 1.5.0, < 2.9.0)
cves:
  - id: CVE-2025-27144
    epss: 0.00385
references:
  - https://github.com/advisories/GHSA-mh25-x5hq-wrqp
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-27144
  - https://github.com/advisories/GHSA-jfm3-95jq-q3rf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Identify applications using vulnerable league/commonmark versions and schedule dependency updates
      owner: Development
      due: 72h
      evidence: Source advisory recommends upgrading to 2.9.0
  mitigation_plan:
    - priority: immediate
      action: Disable vulnerable extensions or slug uniqueness if patching is delayed
      owner: IT Operations
      addresses: CVE-2025-27144
      evidence: Source provided workarounds for non-patchable environments
updates:
  - at: "2026-08-06T21:29:33Z"
    level: L1
    summary: new product
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jfm3-95jq-q3rf
---

The league/commonmark library, specifically versions 2.0.0 through 2.8.x, contains an algorithmic complexity vulnerability (CVE-2025-27144) within its `UniqueSlugNormalizer` component. This component is designed to ensure document-unique heading anchors by appending numeric suffixes to duplicate slugs. However, the implementation resets the search for an unused suffix to index '1' upon every collision. Consequently, processing K colliding slugs results in O(K²) time complexity.

An attacker can exploit this by submitting a Markdown document containing a large number of headings that normalize to the same slug (e.g., identical text, empty headings, or punctuation-only strings). When parsed by applications utilizing extensions such as `HeadingPermalinkExtension`, `FootnoteExtension`, or `TableOfContentsExtension` with the default `PER_DOCUMENT` uniqueness setting, the processor consumes excessive CPU cycles, leading to a denial-of-service condition. Because this behavior occurs during the standard parsing process and requires no authentication, it poses a significant availability risk for web applications that render user-provided Markdown.

## Impact

Successful exploitation results in CPU exhaustion, rendering the affected application unresponsive or significantly degraded. The vulnerability affects any service processing untrusted Markdown input using vulnerable versions of `league/commonmark`. The scale of the impact depends on the configured document size limits; however, even moderately sized inputs can trigger multi-second stalls on a single thread.

## Recommendation

Prioritize upgrading `league/commonmark` to version 2.9.0 or later, which resolves the quadratic behavior. If an immediate upgrade is not feasible, apply one of the following mitigations:

- Set the `slug_normalizer/unique` configuration to `false` (or `UniqueSlugNormalizerInterface::DISABLED`) to stop the de-duplication scan.
- Disable the `HeadingPermalinkExtension`, `TableOfContentsExtension`, and `FootnoteExtension` when processing untrusted input.
- Implement strict upstream constraints on document size or the number of headings allowed in a single input to prevent reaching the threshold where O(K²) complexity becomes destructive.
