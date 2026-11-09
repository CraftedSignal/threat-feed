---
brief_id: brief-2026-11-09-dlink-dir-878-overflow
event_id: brief-2026-11-09-dlink-dir-878-overflow
revision: 1
activity_at: "2026-11-09T06:19:08Z"
title: 'D-Link DIR-878: Heap-based buffer overflow in HNAP handler (CVE-2026-124560)'
slug: 2026-11-dlink-dir-878-overflow
description: A public proof-of-concept exploit is available for a remote heap-based buffer overflow in the D-Link DIR-878 HNAP handler.
date: "2026-11-09T06:19:08Z"
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
products:
  - D-Link DIR-878 (1.20B05)
cves:
  - id: CVE-2026-124560
    cvss: 9.8
    kev_status: "false"
references:
  - https://vuldb.com/cve/CVE-2026-124560
  - https://github.com/Zimo-666/DIR-878-cves/tree/main/01-captcha-uid-heap-overflow
  - https://sploitus.com/exploit?id=CVE-2026-124560&utm_source=rss&utm_medium=rss
---

A vulnerability exists in the D-Link DIR-878 (version 1.20B05) within the `GetCAPTCHAsetting` function of the `bin/prog.cgi` file in the HNAP Handler component. Manipulating the `uid` argument results in a heap-based buffer overflow. The attack can be initiated remotely. The vulnerability affects products no longer supported by the maintainer, and a public proof-of-concept exploit is available.
