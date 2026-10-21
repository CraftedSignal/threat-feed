---
brief_id: brief-2026-10-21-file-management-system-sqli
event_id: brief-2026-10-21-file-management-system-sqli
revision: 1
activity_at: "2026-10-21T17:08:52Z"
title: 'oretnom23 file-management-system-php: SQL injection in Login function (CVE-2026-114254)'
slug: 2026-10-file-management-system-sqli
description: A SQL injection vulnerability exists in the Login function of admin_class.php in oretnom23 file-management-system-php, caused by the manipulation of the username or password arguments.
date: "2026-10-21T17:08:52Z"
lastmod: "2026-10-21T19:16:03Z"
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
vendors:
  - oretnom23
products:
  - oretnom23 file-management-system-php (up to 2e3c1ebe60f121e8df4fb3f544f0e9591d9a01e4)
  - file-management-system-php (up to 2e3c1ebe60f121e8df4fb3f544f0e9591d9a01e4)
cves:
  - id: CVE-2026-114254
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-114255
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114254
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114255
updates:
  - at: "2026-10-21T19:16:03Z"
    level: L2
    summary: added coverage for file-management-system-php (up to 2e3c1ebe60f121e8df4fb3f544f0e9591d9a01e4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114255
---

A vulnerability was identified in oretnom23 file-management-system-php up to 2e3c1ebe60f121e8df4fb3f544f0e9591d9a01e4. The Login function of admin_class.php is susceptible to SQL injection via the manipulation of the username or password arguments. Remote exploitation is possible, and a public exploit exists. The project maintainer has been informed but has not yet responded.
