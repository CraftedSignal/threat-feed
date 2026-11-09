---
brief_id: brief-2026-11-09-dlink-dir878-overflow-8c31ac61
event_id: brief-2026-11-09-dlink-dir878-overflow-8c31ac61
revision: 1
activity_at: "2026-11-09T07:31:51Z"
title: 'D-Link DIR-878: Buffer overflow in HNAP Handler (CVE-2026-124562)'
slug: 2026-11-dlink-dir878-overflow-8c31ac61
description: A buffer overflow vulnerability exists in the HNAP Handler component of the D-Link DIR-878 (version 1.20B05), reachable via remote attack.
date: "2026-11-09T07:31:51Z"
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
cpes:
  - cpe:2.3:a:d_link:dir_878:*:*:*:*:*:*:*:*
vendors:
  - D-Link
products:
  - DIR-878 (1.20B05)
cves:
  - id: CVE-2026-124562
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124562
---

A vulnerability was identified in the SetWanSettings function of the HNAP Handler component in D-Link DIR-878 version 1.20B05. Manipulation of the ConfigDNS/Primary or ConfigDNS/Secondary arguments leads to a buffer overflow. This vulnerability is remotely exploitable. The exploit is publicly available and might be used. The affected product is no longer supported by the maintainer.
