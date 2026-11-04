---
brief_id: brief-2026-11-04-ibm-mq-rce
event_id: brief-2026-11-04-ibm-mq-rce
revision: 1
activity_at: "2026-11-04T22:07:22Z"
title: 'IBM MQ: Managed File Transfer agent arbitrary code execution (CVE-2026-11724)'
slug: 2026-11-ibm-mq-rce
description: IBM MQ Managed File Transfer (MFT) contains a vulnerability that could allow an authenticated attacker to execute arbitrary code on an agent host due to improper validation of metadata used during script execution.
date: "2026-11-04T22:07:22Z"
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
  - IBM MQ 9.2.0.0 through 9.2.0.44 LTS
  - IBM MQ 9.3.0.0 through 9.3.0.42 LTS
  - IBM MQ 9.4.0.0 through 9.4.0.26 LTS
  - IBM MQ 9.4.0.0 through 9.4.5.1 CD
  - IBM MQ 10.0.0.0 through 10.0.0.5 LTS and CD
cves:
  - id: CVE-2026-11724
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11724
---

CVE-2026-11724 affects IBM MQ 9.2.0.0 through 9.2.0.44 LTS, 9.3.0.0 through 9.3.0.42 LTS, 9.4.0.0 through 9.4.0.26 LTS, 9.4.0.0 through 9.4.5.1 CD, and 10.0.0.0 through 10.0.0.5 LTS and CD. The vulnerability permits an authenticated attacker to execute arbitrary code on an MFT agent host by exploiting improper metadata validation during script execution.
