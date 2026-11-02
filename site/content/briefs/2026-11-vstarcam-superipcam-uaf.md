---
brief_id: brief-2026-11-02-vstarcam-superipcam-uaf
event_id: brief-2026-11-02-vstarcam-superipcam-uaf
revision: 1
activity_at: "2026-11-02T07:17:05Z"
title: 'VStarcam O-KAM SuperIPCam: Use-after-free vulnerability (CVE-2026-120337)'
slug: 2026-11-vstarcam-superipcam-uaf
description: A use-after-free vulnerability exists in the P2P Session Teardown component of VStarcam O-KAM SuperIPCam 1.3.3.32.
date: "2026-11-02T07:17:05Z"
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
  - cpe:2.3:a:vstarcam:o_kam_superipcam:*:*:*:*:*:*:*:*
vendors:
  - VStarcam
products:
  - O-KAM SuperIPCam (1.3.3.32)
cves:
  - id: CVE-2026-120337
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120337
---

CVE-2026-120337 is a use-after-free vulnerability in VStarcam O-KAM SuperIPCam version 1.3.3.32. The vulnerability affects the function FUN_005a2d44 of SuperIPCam.exe within the P2P Session Teardown component. The vulnerability can be initiated remotely. Public exploit code has been disclosed. The vendor was contacted but did not respond.
