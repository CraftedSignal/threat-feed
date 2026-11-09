---
brief_id: brief-2026-11-09-fv-flowplayer-xss
event_id: brief-2026-11-09-fv-flowplayer-xss
revision: 1
activity_at: "2026-11-09T11:39:43Z"
title: 'FolioVision FV Flowplayer Video Player: Stored Cross-site Scripting (CVE-2026-121764)'
slug: 2026-11-fv-flowplayer-xss
description: The FolioVision FV Flowplayer Video Player plugin for WordPress contains a Stored Cross-site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
date: "2026-11-09T11:39:43Z"
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
  - cpe:2.3:a:foliovision:fv_flowplayer_video_player:*:*:*:*:*:*:*:*
vendors:
  - FolioVision
products:
  - FV Flowplayer Video Player (n/a through 7.5.56.7212)
cves:
  - id: CVE-2026-121764
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121764
---

CVE-2026-121764 identifies a Stored Cross-site Scripting (XSS) vulnerability in the FolioVision FV Flowplayer Video Player plugin for WordPress. The issue arises from improper neutralization of input during web page generation. This vulnerability affects versions from n/a through 7.5.56.7212.
