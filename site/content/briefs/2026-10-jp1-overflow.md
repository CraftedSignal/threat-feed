---
brief_id: brief-2026-10-27-jp1-overflow
event_id: brief-2026-10-27-jp1-overflow
revision: 1
activity_at: "2026-10-27T10:56:07Z"
title: 'JP1/Automatic Job Management System 3: Stack-based buffer overflow (CVE-2026-76932)'
slug: 2026-10-jp1-overflow
description: A stack-based buffer overflow vulnerability has been identified in JP1/Automatic Job Management System 3.
date: "2026-10-27T10:56:07Z"
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
products:
  - JP1/Automatic Job Management System 3 - Manager (11-00 <= v < 13-50-31)
  - JP1/Automatic Job Management System 3 - Agent (11-00 <= v < 13-50-31)
cves:
  - id: CVE-2026-76932
    cvss: 9.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76932
---

CVE-2026-76932 identifies a stack-based buffer overflow vulnerability in JP1/Automatic Job Management System 3. 

Affected components and versions:
- JP1/Automatic Job Management System 3 - Manager: from 11-00 before 13-50-31
- JP1/Automatic Job Management System 3 - Agent: from 11-00 before 13-50-31

CVSS v3.1 Base Score: 9.4
