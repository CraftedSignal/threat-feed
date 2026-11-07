---
brief_id: brief-2026-11-07-ibm-api-connect-path-traversal-40cd63e4
event_id: brief-2026-11-07-ibm-api-connect-path-traversal-40cd63e4
revision: 1
activity_at: "2026-11-07T07:50:52Z"
title: 'IBM API Connect: Arbitrary file write via path traversal (CVE-2026-17354)'
slug: 2026-11-ibm-api-connect-path-traversal-40cd63e4
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to a path traversal vulnerability that enables a remote authenticated attacker to perform arbitrary file writes.
date: "2026-11-07T07:50:52Z"
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
  - API Connect (12.1.0.0-12.1.1.2)
cves:
  - id: CVE-2026-17354
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17354
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a path traversal vulnerability. A remote authenticated attacker can exploit this flaw to perform arbitrary file writes.
