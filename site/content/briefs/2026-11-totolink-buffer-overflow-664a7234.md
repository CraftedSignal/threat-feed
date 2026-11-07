---
brief_id: brief-2026-11-07-totolink-buffer-overflow-664a7234
event_id: brief-2026-11-07-totolink-buffer-overflow-664a7234
revision: 1
activity_at: "2026-11-07T22:10:38Z"
title: 'TOTOLINK CA300-PoE: Remote buffer overflow in setWiFiMultipleConfig (CVE-2026-124057)'
slug: 2026-11-totolink-buffer-overflow-664a7234
description: A remote buffer overflow vulnerability has been identified in the TOTOLINK CA300-PoE function setWiFiMultipleConfig.
date: "2026-11-07T22:10:38Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:totolink:ca300_poe:*:*:*:*:*:*:*:*
vendors:
  - TOTOLINK
products:
  - CA300-PoE
cves:
  - id: CVE-2026-124057
    cvss: 9.1
    kev_status: "false"
references:
  - https://vuldb.com/vuln/432112
  - https://sploitus.com/exploit?id=CVE-2026-124057
  - https://sploitus.com/exploit?id=CVE-2026-124057&utm_source=rss&utm_medium=rss
---

CVE-2026-124057 is a remote buffer overflow vulnerability in the TOTOLINK CA300-PoE. The flaw exists in the `setWiFiMultipleConfig` function within `/cgi-bin/cstecgi.cgi`. Manipulation of the `Key1Str1` argument triggers the overflow. A public exploit for this vulnerability is available.
