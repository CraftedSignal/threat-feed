---
brief_id: brief-2026-10-29-langflow-rce
event_id: brief-2026-10-29-langflow-rce
revision: 3
activity_at: "2026-10-29T20:15:56Z"
revision_history:
  - revision: 2
    at: "2026-10-29T18:44:03Z"
    checksum: sha256:08ecd4e498a2184ecb96f945b3306bc6aea5f6529871804715d0c237be52c9c1
    summary: added CVE-2026-107327
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-107327
  - revision: 3
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:0eb317797eecb6929e1b63e69f8b9ed0c8bc22c15b89868b58339c5d39eaae4c
    summary: added CVE-2026-110186
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110186
title: 'IBM Langflow OSS: Arbitrary code execution via eval/exec (CVE-2026-107328)'
slug: 2026-10-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.12.4 are vulnerable to remote code execution due to improper neutralization of code in eval/exec functions by a remote authenticated attacker.
date: "2026-10-29T17:30:37Z"
lastmod: "2026-10-29T20:15:22Z"
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
  - Langflow OSS (1.0.0 through 1.12.8)
cves:
  - id: CVE-2026-107328
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-107327
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-110186
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107328
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107327
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110186
updates:
  - at: "2026-10-29T18:42:34Z"
    level: L2
    summary: added CVE-2026-107327
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-107327
  - at: "2026-10-29T20:15:22Z"
    level: L2
    summary: added CVE-2026-110186
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110186
---

IBM Langflow OSS versions 1.0.0 through 1.12.4 allow a remote authenticated attacker to execute arbitrary code. This vulnerability is caused by improper neutralization of code in eval/exec.
