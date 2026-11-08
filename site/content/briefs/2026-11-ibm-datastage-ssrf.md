---
brief_id: brief-2026-11-08-ibm-datastage-ssrf
event_id: brief-2026-11-08-ibm-datastage-ssrf
revision: 1
activity_at: "2026-11-08T19:34:28Z"
title: 'IBM Cloud Pak for Data: DataStage Server-Side Request Forgery (CVE-2026-107330)'
slug: 2026-11-ibm-datastage-ssrf
description: IBM DataStage on Cloud Pak for Data 5.4.0.0 is vulnerable to a Server-Side Request Forgery (SSRF) flaw that could allow a remote authenticated attacker to obtain sensitive information.
date: "2026-11-08T19:34:28Z"
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
  - cpe:2.3:a:ibm:cloud_pak_for_data_5_4_0_0:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Cloud Pak for Data 5.4.0.0
cves:
  - id: CVE-2026-107330
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107330
---

IBM DataStage on Cloud Pak for Data 5.4.0.0 contains a Server-Side Request Forgery (SSRF) vulnerability. This vulnerability could allow a remote authenticated attacker to obtain sensitive information.
