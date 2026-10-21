---
brief_id: brief-2026-10-21-tenda-be3l-pro-buffer-overflow
event_id: brief-2026-10-21-tenda-be3l-pro-buffer-overflow
revision: 1
activity_at: "2026-10-21T21:37:20Z"
title: 'Tenda BE3L Pro: Buffer overflow in formWifiBasicSet (CVE-2026-114268)'
slug: 2026-10-tenda-be3l-pro-buffer-overflow
description: A buffer overflow vulnerability exists in the Tenda BE3L Pro (version 16.03.60.62) within the formWifiBasicSet function of the /goform/WifiBasicSet file. The flaw is triggered via the security_5g argument and can be initiated remotely.
date: "2026-10-21T21:37:20Z"
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
  - cpe:2.3:a:tenda:be3l_pro:*:*:*:*:*:*:*:*
vendors:
  - Tenda
products:
  - BE3L Pro (16.03.60.62)
cves:
  - id: CVE-2026-114268
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114268
---

A flaw has been found in Tenda BE3L Pro 16.03.60.62. The function formWifiBasicSet in the file /goform/WifiBasicSet is affected by a buffer overflow vulnerability. This is caused by manipulation of the security_5g argument. The attack can be initiated remotely. An exploit has been published.
