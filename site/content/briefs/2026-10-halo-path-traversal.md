---
brief_id: brief-2026-10-26-halo-path-traversal
event_id: brief-2026-10-26-halo-path-traversal
revision: 1
activity_at: "2026-10-26T05:34:52Z"
title: 'Halo: Path traversal in View Name Resolver (CVE-2026-116117)'
slug: 2026-10-halo-path-traversal
description: A path traversal vulnerability exists in the halo-dev halo View Name Resolver component (up to 2.27.0-beta.1) via the template argument.
date: "2026-10-26T05:34:52Z"
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
cpes:
  - cpe:2.3:a:halo_dev:halo:*:*:*:*:*:*:*:*
vendors:
  - halo-dev
products:
  - halo (up to 2.27.0-beta.1)
cves:
  - id: CVE-2026-116117
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116117
---

A flaw has been identified in halo-dev halo up to 2.27.0-beta.1, specifically within the function `run.halo.app.theme.DefaultViewNameResolver.resolveViewNameOrDefault`. Manipulation of the `template` argument can lead to path traversal. The attack can be launched remotely. Exploit code has been published. The vendor did not respond to disclosure.
