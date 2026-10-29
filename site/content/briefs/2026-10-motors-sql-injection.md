---
brief_id: brief-2026-10-29-motors-sql-injection
event_id: brief-2026-10-29-motors-sql-injection
revision: 1
activity_at: "2026-10-29T20:39:48Z"
title: 'StylemixThemes Motors: Blind SQL injection (CVE-2026-115964)'
slug: 2026-10-motors-sql-injection
description: The StylemixThemes Motors motors-car-dealership-classified-listings component contains an SQL injection vulnerability allowing Blind SQL Injection.
date: "2026-10-29T20:39:48Z"
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
  - cpe:2.3:a:stylemixthemes:motors_car_dealership_classified_listings:*:*:*:*:*:*:*:*
vendors:
  - StylemixThemes
products:
  - motors-car-dealership-classified-listings (n/a through 1.4.126)
cves:
  - id: CVE-2026-115964
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115964
---

CVE-2026-115964 describes an Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in StylemixThemes Motors motors-car-dealership-classified-listings, which allows Blind SQL Injection. This issue affects versions from n/a through 1.4.126.
