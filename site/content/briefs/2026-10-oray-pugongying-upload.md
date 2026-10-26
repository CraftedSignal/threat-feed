---
brief_id: brief-2026-10-26-oray-pugongying-upload
event_id: brief-2026-10-26-oray-pugongying-upload
revision: 1
activity_at: "2026-10-26T09:40:54Z"
title: 'Oray Pugongying X5 Pro: Unrestricted file upload in PPPoE WAN Setting (CVE-2026-116236)'
slug: 2026-10-oray-pugongying-upload
description: A vulnerability in Oray Pugongying X5 Pro 7.6.1 allows for remote unrestricted file uploads via the PPPoE WAN Setting Handler.
date: "2026-10-26T09:40:54Z"
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
  - cpe:2.3:a:oray:pugongying_x5_pro_7_6_1:*:*:*:*:*:*:*:*
vendors:
  - Oray
products:
  - Pugongying X5 Pro 7.6.1
cves:
  - id: CVE-2026-116236
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116236
---

A vulnerability exists in Oray Pugongying X5 Pro version 7.6.1 within the `plugin_init` function of the `/tmp/upload_files` file, used by the PPPoE WAN Setting Handler. Manipulation of the `pppd_options` argument allows for unrestricted file uploads. The attack can be launched remotely. Public exploits are available, and the vendor has not responded to disclosure attempts.
