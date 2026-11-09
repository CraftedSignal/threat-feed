---
brief_id: brief-2026-11-09-cpython-cookiejar-vuln
event_id: brief-2026-11-09-cpython-cookiejar-vuln
revision: 1
activity_at: "2026-11-09T23:17:34Z"
title: 'CPython: http.cookiejar deletes cookies of other domains via expired Set-Cookie (CVE-2026-124249)'
slug: 2026-11-cpython-cookiejar-vuln
description: CPython's http.cookiejar module is vulnerable to the deletion of cookies belonging to other domains when an expired Set-Cookie header is processed.
date: "2026-11-09T23:17:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: unknown
cpes:
  - cpe:2.3:a:python_software_foundation:cpython:*:*:*:*:*:*:*:*
vendors:
  - Python Software Foundation
products:
  - CPython
cves:
  - id: CVE-2026-124249
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/604
---

A security vulnerability (CVE-2026-124249) has been identified in the CPython `http.cookiejar` module. The module improperly handles expired `Set-Cookie` headers, resulting in the deletion of cookies associated with other domains.
