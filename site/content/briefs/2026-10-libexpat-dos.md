---
brief_id: brief-2026-10-23-libexpat-dos
event_id: brief-2026-10-23-libexpat-dos
revision: 1
activity_at: "2026-10-23T07:36:31Z"
title: 'libexpat: Denial of service via XML entity amplification (CVE-2026-115506)'
slug: 2026-10-libexpat-dos
description: libexpat through 2.9.0 is vulnerable to a denial of service attack because the billion laughs protection in accountingDiffTolerated() detects entity amplification too late.
date: "2026-10-23T07:36:31Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - libexpat (<= 2.9.0)
cves:
  - id: CVE-2026-115506
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115506
---

libexpat through 2.9.0 contains a denial of service vulnerability because the billion laughs protection in accountingDiffTolerated() within xmlparse.c detects entity amplification too late. Attackers can supply a moderately sized XML document with a large DTD and nested entity expansions to consume tens of seconds of CPU per parse.
