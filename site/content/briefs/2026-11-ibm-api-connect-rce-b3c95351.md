---
brief_id: brief-2026-11-07-ibm-api-connect-rce-b3c95351
event_id: brief-2026-11-07-ibm-api-connect-rce-b3c95351
revision: 1
activity_at: "2026-11-07T05:59:34Z"
title: 'IBM API Connect: Arbitrary code execution (CVE-2026-105002)'
slug: 2026-11-ibm-api-connect-rce-b3c95351
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 may allow arbitrary code execution in the management service due to improper control of generation of code.
date: "2026-11-07T05:59:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
cves:
  - id: CVE-2026-105002
    cvss: 7.5
    kev_status: "false"
references:
  - CVE-2026-105002
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105002
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a vulnerability that could allow arbitrary code to be executed by the management service in certain non-default configurations. This is caused by improper control of generation of code, where customization content may be evaluated as code. This vulnerability is only possible where the related feature is enabled and not properly restricted.
