---
brief_id: brief-2026-10-31-follow-redirects-sensitive-header-disclosure
event_id: brief-2026-10-31-follow-redirects-sensitive-header-disclosure
revision: 1
activity_at: "2026-10-31T03:20:31Z"
title: 'follow-redirects: Sensitive header disclosure via cross-realm array validation (CVE-2026-116689)'
slug: 2026-10-follow-redirects-sensitive-header-disclosure
description: The follow-redirects package (versions 1.16.0 - 1.16.1) fails to identify sensitive header arrays created in isolated JavaScript realms, leading to the accidental forwarding of sensitive credentials to attacker-controlled redirect destinations.
date: "2026-10-31T03:20:31Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - follow-redirects (>= 1.16.0, <= 1.16.1)
cves:
  - id: CVE-2026-116689
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-mrwp-f3q8-3g9p
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116689
---

The `follow-redirects` library validates the `sensitiveHeaders` option using `instanceof Array`. This check fails when an array is instantiated within a separate JavaScript realm (e.g., `node:vm`). In such cases, the library silently resets the `sensitiveHeaders` to an empty list. Consequently, custom headers listed in the array - such as API keys or service tokens - are not scrubbed and are forwarded during cross-origin redirects. Built-in headers including `Authorization`, `Proxy-Authorization`, and `Cookie` are not affected.
