---
brief_id: brief-2026-11-08-jinher-oa-c6-sql-injection
event_id: brief-2026-11-08-jinher-oa-c6-sql-injection
revision: 1
activity_at: "2026-11-08T19:33:33Z"
title: 'Jinher OA C6: SQL injection in ProjectAfficheManage.aspx (CVE-2026-124331)'
slug: 2026-11-jinher-oa-c6-sql-injection
description: A SQL injection vulnerability exists in Jinher OA C6 within the ProjectAfficheManage.aspx file.
date: "2026-11-08T19:33:33Z"
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
  - cpe:2.3:a:jinher:oa_c6:*:*:*:*:*:*:*:*
vendors:
  - Jinher
products:
  - OA C6
cves:
  - id: CVE-2026-124331
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124331
---

A vulnerability was identified in Jinher OA C6 in the file /C6/JHSoft.Web.Project/OfficeReadOnly/ProjectAfficheManage.aspx. Manipulation of the ProjID argument leads to SQL injection. The attack can be launched remotely. Public exploit code is available. The vendor was contacted but did not respond.
