---
brief_id: brief-2026-11-09-jetformbuilder-xss-5b766bb3
event_id: brief-2026-11-09-jetformbuilder-xss-5b766bb3
revision: 1
activity_at: "2026-11-09T17:50:56Z"
title: 'Crocoblock JetFormBuilder: Stored Cross-site Scripting (CVE-2026-123482)'
slug: 2026-11-jetformbuilder-xss-5b766bb3
description: Crocoblock JetFormBuilder is affected by an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability.
date: "2026-11-09T17:50:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:crocoblock:jetformbuilder:*:*:*:*:*:*:*:*
vendors:
  - Crocoblock
products:
  - JetFormBuilder (n/a through 3.6.8)
cves:
  - id: CVE-2026-123482
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123482
---

Crocoblock JetFormBuilder (from n/a through 3.6.8) is affected by a Stored Cross-site Scripting (XSS) vulnerability, tracked as CVE-2026-123482. This issue is caused by improper neutralization of input during web page generation.
