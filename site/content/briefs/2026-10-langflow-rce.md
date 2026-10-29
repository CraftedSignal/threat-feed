---
brief_id: brief-2026-10-29-langflow-rce
event_id: brief-2026-10-29-langflow-rce
revision: 1
activity_at: "2026-10-29T17:30:37Z"
title: 'IBM Langflow OSS: Arbitrary code execution via eval/exec (CVE-2026-107328)'
slug: 2026-10-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.12.4 are vulnerable to remote code execution due to improper neutralization of code in eval/exec functions by a remote authenticated attacker.
date: "2026-10-29T17:30:37Z"
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
  - cpe:2.3:a:ibm:langflow_oss:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 through 1.12.4)
cves:
  - id: CVE-2026-107328
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107328
---

IBM Langflow OSS versions 1.0.0 through 1.12.4 allow a remote authenticated attacker to execute arbitrary code. This vulnerability is caused by improper neutralization of code in eval/exec.
