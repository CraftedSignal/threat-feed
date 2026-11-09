---
brief_id: brief-2026-11-09-videowhisper-xss
event_id: brief-2026-11-09-videowhisper-xss
revision: 1
activity_at: "2026-11-09T17:50:48Z"
title: 'VideoWhisper Broadcast Live Video: Reflected Cross-site Scripting (CVE-2026-122664)'
slug: 2026-11-videowhisper-xss
description: The VideoWhisper.com Broadcast Live Video plugin is vulnerable to Reflected Cross-site Scripting (XSS) due to improper neutralization of input during web page generation.
date: "2026-11-09T17:50:48Z"
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
  - cpe:2.3:a:videowhisper:broadcast_live_video:*:*:*:*:*:*:*:*
vendors:
  - VideoWhisper
products:
  - Broadcast Live Video (n/a through 7.3.14)
cves:
  - id: CVE-2026-122664
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122664
---

VideoWhisper.com Broadcast Live Video (videowhisper-live-streaming-integration) is affected by a Reflected Cross-site Scripting (XSS) vulnerability (CVE-2026-122664). This issue affects versions from n/a through 7.3.14.
