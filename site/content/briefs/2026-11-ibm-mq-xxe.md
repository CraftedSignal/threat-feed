---
brief_id: brief-2026-11-04-ibm-mq-xxe
event_id: brief-2026-11-04-ibm-mq-xxe
revision: 1
activity_at: "2026-11-04T22:10:20Z"
title: 'IBM MQ: XML External Entity Injection (CVE-2026-13284)'
slug: 2026-11-ibm-mq-xxe
description: IBM MQ versions 9.2.0.0 through 9.2.0.44 LTS, 9.3.0.0 through 9.3.0.42 LTS, 9.4.0.0 through 9.4.0.26 LTS, 9.4.0.0 through 9.4.5.1 CD, and 10.0.0.0 through 10.0.0.5 LTS and CD are vulnerable to an XML external entity (XXE) injection attack when processing XML data.
date: "2026-11-04T22:10:20Z"
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
  - IBM
products:
  - MQ 9.2.0.0 through 9.2.0.44 LTS
  - MQ 9.3.0.0 through 9.3.0.42 LTS
  - MQ 9.4.0.0 through 9.4.0.26 LTS
  - MQ 9.4.0.0 through 9.4.5.1 CD
  - MQ 10.0.0.0 through 10.0.0.5 LTS and CD
cves:
  - id: CVE-2026-13284
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13284
---

IBM MQ is vulnerable to an XML external entity (XXE) injection attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources.
