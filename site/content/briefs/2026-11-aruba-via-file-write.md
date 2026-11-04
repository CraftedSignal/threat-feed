---
brief_id: brief-2026-11-04-aruba-via-file-write
event_id: brief-2026-11-04-aruba-via-file-write
revision: 1
activity_at: "2026-11-04T02:27:54Z"
title: Virtual Intranet Access (VIA) client arbitrary file write (CVE-2026-95728)
slug: 2026-11-aruba-via-file-write
description: An arbitrary file write vulnerability exists in the Virtual Intranet Access (VIA) client, which could allow a local attacker with low privileges to escalate privileges on the affected system.
date: "2026-11-04T02:27:54Z"
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
products:
  - Virtual Intranet Access (VIA)
cves:
  - id: CVE-2026-95728
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95728
---

CVE-2026-95728 describes an arbitrary file write vulnerability within the Virtual Intranet Access (VIA) client. Successful exploitation could allow a local attacker with low privileges to escalate privileges on the affected system.
