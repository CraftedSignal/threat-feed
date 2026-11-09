---
brief_id: brief-2026-11-09-jeecgboot-sqli
event_id: brief-2026-11-09-jeecgboot-sqli
revision: 1
activity_at: "2026-11-09T03:24:09Z"
title: 'JeecgBoot JimuBI: SQL injection vulnerability (CVE-2026-124554)'
slug: 2026-11-jeecgboot-sqli
description: A security flaw in JeecgBoot 3.9.5 allows for SQL injection via the params argument in the getAllChartData endpoint of the JimuBI component.
date: "2026-11-09T03:24:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - JeecgBoot 3.9.5
cves:
  - id: CVE-2026-124554
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124554
---

A security flaw has been discovered in JeecgBoot 3.9.5 affecting the component JimuBI, specifically the file /jeecg-boot/drag/onlDragDatasetHead/getAllChartData. Manipulation of the 'params' argument results in SQL injection. Remote exploitation is possible, and public exploit code has been released. The vendor was contacted but did not respond.
