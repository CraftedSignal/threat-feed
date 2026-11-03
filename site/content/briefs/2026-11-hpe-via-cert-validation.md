---
brief_id: brief-2026-11-03-hpe-via-cert-validation
event_id: brief-2026-11-03-hpe-via-cert-validation
revision: 1
activity_at: "2026-11-03T22:20:59Z"
title: 'HPE Networking Virtual Intranet Access: Authentication bypass via improper certificate validation (CVE-2026-95724)'
slug: 2026-11-hpe-via-cert-validation
description: HPE Networking Virtual Intranet Access (VIA) contains an improper certificate validation vulnerability that allows an unauthenticated remote attacker to bypass authentication mechanisms, leading to the possible disclosure of sensitive information.
date: "2026-11-03T22:20:59Z"
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
  - cpe:2.3:a:hpe:networking_virtual_intranet_access:*:*:*:*:*:*:*:*
vendors:
  - HPE
products:
  - Networking Virtual Intranet Access (VIA)
cves:
  - id: CVE-2026-95724
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95724
---

An improper certificate validation vulnerability exists in HPE Networking Virtual Intranet Access (VIA). Successful exploitation could allow an unauthenticated remote attacker to bypass authentication mechanisms, leading to the possible disclosure of sensitive information.
