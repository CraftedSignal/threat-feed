---
brief_id: brief-2026-11-08-ibm-concert-rce
event_id: brief-2026-11-08-ibm-concert-rce
revision: 1
activity_at: "2026-11-08T19:33:11Z"
title: 'IBM Concert: Arbitrary command execution (CVE-2026-15266)'
slug: 2026-11-ibm-concert-rce
description: IBM Concert versions 1.0 through 3.0.1.1 contain components that allow potentially unsafe command execution, which could be exploited to run arbitrary system commands on the host.
date: "2026-11-08T19:33:11Z"
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
  - cpe:2.3:a:ibm:concert:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Concert (1.0 through 3.0.1.1)
cves:
  - id: CVE-2026-15266
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15266
---

IBM Concert versions 1.0 through 3.0.1.1 contain components that allow potentially unsafe command execution. This vulnerability could be exploited to run arbitrary system commands on the host. The issue has been assigned a CVSS v3.1 base score of 9.8.
