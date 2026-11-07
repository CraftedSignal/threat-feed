---
brief_id: brief-2026-11-07-ibm-api-connect-traversal-99d3af6d
event_id: brief-2026-11-07-ibm-api-connect-traversal-99d3af6d
revision: 1
activity_at: "2026-11-07T06:01:31Z"
title: 'IBM API Connect: Path traversal information disclosure (CVE-2026-16880)'
slug: 2026-11-ibm-api-connect-traversal-99d3af6d
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a path traversal vulnerability that could allow a remote authenticated attacker to obtain sensitive information.
date: "2026-11-07T06:01:31Z"
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
  - IBM API Connect 10.0.8.0 through 10.0.8.12
  - IBM API Connect 12.1.0.0 through 12.1.1.2
cves:
  - id: CVE-2026-16880
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16880
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to path traversal.
