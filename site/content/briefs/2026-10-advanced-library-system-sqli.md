---
brief_id: brief-2026-10-21-advanced-library-system-sqli
event_id: brief-2026-10-21-advanced-library-system-sqli
revision: 1
activity_at: "2026-10-21T19:57:37Z"
title: ProjectWorlds Advanced Library Management System SQL Injection (CVE-2026-114263)
slug: 2026-10-advanced-library-system-sqli
description: A vulnerability in ProjectWorlds Advanced Library Management System 1.0 allows remote SQL injection via the roll_number argument in individual_report_search.php.
date: "2026-10-21T19:57:37Z"
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
  - ProjectWorlds Advanced Library Management System 1.0
cves:
  - id: CVE-2026-114263
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114263
---

A vulnerability was identified in ProjectWorlds Advanced Library Management System 1.0. The function mysqli_query in the file individual_report_search.php is susceptible to SQL injection through the manipulation of the roll_number argument. The attack may be launched remotely, and public exploit code is available.
