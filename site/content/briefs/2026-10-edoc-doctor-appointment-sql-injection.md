---
brief_id: brief-2026-10-26-edoc-doctor-appointment-sql-injection
event_id: brief-2026-10-26-edoc-doctor-appointment-sql-injection
revision: 1
activity_at: "2026-10-26T09:40:45Z"
title: HashenUdara edoc-doctor-appointment-system SQL Injection (CVE-2026-116112)
slug: 2026-10-edoc-doctor-appointment-sql-injection
description: A SQL injection vulnerability exists in the admin/add-new.php file of the edoc-doctor-appointment-system via the spec parameter.
date: "2026-10-26T09:40:45Z"
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
  - cpe:2.3:a:hashenudara:edoc-doctor-appointment-system:*:*:*:*:*:*:*:*
vendors:
  - HashenUdara
products:
  - edoc-doctor-appointment-system (<= cc258425b915d1af9e298777ccd26d160493e68d)
cves:
  - id: CVE-2026-116112
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116112
---

CVE-2026-116112 is a SQL injection vulnerability in HashenUdara edoc-doctor-appointment-system up to commit cc258425b915d1af9e298777ccd26d160493e68d. The flaw exists in the admin/add-new.php file, where manipulation of the 'spec' argument leads to SQL injection. The attack can be initiated remotely. Public exploit code is available. The vendor did not respond to disclosure efforts. Due to the project's rolling release model, no specific version details for affected or updated releases are available.
