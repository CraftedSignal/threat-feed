---
brief_id: brief-2026-11-07-ibm-api-connect-xxe
event_id: brief-2026-11-07-ibm-api-connect-xxe
revision: 1
activity_at: "2026-11-07T05:49:28Z"
title: 'IBM API Connect: XML External Entity (XXE) injection (CVE-2026-16884)'
slug: 2026-11-ibm-api-connect-xxe
description: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote attacker to obtain sensitive information due to an XML external entity (XXE) injection.
date: "2026-11-07T05:49:28Z"
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
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
cves:
  - id: CVE-2026-16884
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16884
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to an XML external entity (XXE) injection. This vulnerability could allow a remote attacker to obtain sensitive information.
