---
brief_id: brief-2026-11-09-ibm-sevone-dos
event_id: brief-2026-11-09-ibm-sevone-dos
revision: 1
activity_at: "2026-11-09T01:23:52Z"
title: 'IBM SevOne Network Performance Management: Uncontrolled resource consumption (CVE-2026-96146)'
slug: 2026-11-ibm-sevone-dos
description: IBM SevOne Network Performance Management 7.0.0 through 8.2.2 could allow a remote attacker to cause a denial of service due to uncontrolled resource consumption.
date: "2026-11-09T01:23:52Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:ibm:sevone_network_performance_management:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - SevOne Network Performance Management (7.0.0 through 8.2.2)
cves:
  - id: CVE-2026-96146
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96146
---

IBM SevOne Network Performance Management versions 7.0.0 through 8.2.2 contain an uncontrolled resource consumption vulnerability (CVE-2026-96146). A remote attacker can exploit this to cause a denial of service. The CVSS v3.1 base score for this vulnerability is 7.5.
