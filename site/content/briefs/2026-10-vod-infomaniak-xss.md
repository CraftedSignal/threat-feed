---
brief_id: brief-2026-10-24-vod-infomaniak-xss
event_id: brief-2026-10-24-vod-infomaniak-xss
revision: 1
activity_at: "2026-10-24T10:12:35Z"
title: 'VOD Infomaniak: Stored Cross-Site Scripting (CVE-2026-114695)'
slug: 2026-10-vod-infomaniak-xss
description: VOD Infomaniak contains a Stored Cross-site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
date: "2026-10-24T10:12:35Z"
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
  - cpe:2.3:a:infomaniak_network:vod_infomaniak:*:*:*:*:*:*:*:*
vendors:
  - Infomaniak Network
products:
  - VOD Infomaniak (n/a through 1.5.14)
cves:
  - id: CVE-2026-114695
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114695
---

A Stored Cross-site Scripting (XSS) vulnerability exists in Infomaniak Network VOD Infomaniak. The vulnerability arises from improper neutralization of input during web page generation. This issue affects VOD Infomaniak from n/a through 1.5.14.
