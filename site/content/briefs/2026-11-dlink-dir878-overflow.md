---
brief_id: brief-2026-11-09-dlink-dir878-overflow
event_id: brief-2026-11-09-dlink-dir878-overflow
revision: 1
activity_at: "2026-11-09T05:28:48Z"
title: 'D-Link DIR-878: SetWanSettings buffer overflow (CVE-2026-124563)'
slug: 2026-11-dlink-dir878-overflow
description: A buffer overflow vulnerability in the SetWanSettings function of the D-Link DIR-878 (1.20B05) HNAP Handler component allows for remote exploitation. Public exploits are available.
date: "2026-11-09T05:28:48Z"
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
tags:
  - cve-2026-124563
  - buffer-overflow
vendors:
  - D-Link
products:
  - DIR-878 (1.20B05)
cves:
  - id: CVE-2026-124563
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124563
---

A security flaw has been discovered in the HNAP Handler component of D-Link DIR-878 firmware version 1.20B05. Manipulation of the Primary or Secondary arguments in the SetWanSettings function results in a buffer overflow. The attack can be launched remotely. The exploit has been released to the public. This vulnerability only affects products that are no longer supported by the maintainer.
