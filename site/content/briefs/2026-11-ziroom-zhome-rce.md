---
brief_id: brief-2026-11-03-ziroom-zhome-rce
event_id: brief-2026-11-03-ziroom-zhome-rce
revision: 1
activity_at: "2026-11-03T18:02:33Z"
title: 'Ziroom ZHOME A0101: Code injection in Lua Handler (CVE-2026-121260)'
slug: 2026-11-ziroom-zhome-rce
description: A flaw in the Lua Handler of Ziroom ZHOME A0101 1.0.1.0 Build 202004151405 allows remote code injection via the loadstring function.
date: "2026-11-03T18:02:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:ziroom:zhome_a0101:*:*:*:*:*:*:*:*
vendors:
  - Ziroom
products:
  - ZHOME A0101 (1.0.1.0 Build 202004151405)
cves:
  - id: CVE-2026-121260
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121260
---

A flaw has been identified in the `loadstring` function of the file `usr/lib/lua/luci/controller/api/zrUsb.lua` within the Lua Handler component of Ziroom ZHOME A0101 1.0.1.0 Build 202004151405. This manipulation results in code injection. The vulnerability is remotely exploitable, and public exploit code is available. The vendor was contacted but did not respond.
