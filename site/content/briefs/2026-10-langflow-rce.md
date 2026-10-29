---
brief_id: brief-2026-10-29-langflow-rce
event_id: brief-2026-10-29-langflow-rce
revision: 4
activity_at: "2026-10-29T20:19:26Z"
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
  - revision: 4
    at: "2026-10-29T20:19:26Z"
    checksum: sha256:01851eade2342d0a463d8f102f9acfdaca26c5d7106835f3fd3eef31f2f04447
    summary: added coverage for Langflow OSS (1.0.0 through 1.12.4)
    changed_fields:
      - action_plan
      - affected_products
      - claim_state
      - cpes
      - cves
      - lastmod
      - qa_status
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110244
title: 'IBM Langflow OSS: Arbitrary code execution via eval/exec (CVE-2026-107328)'
slug: 2026-10-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.12.4 are vulnerable to remote code execution due to improper neutralization of code in eval/exec functions by a remote authenticated attacker.
date: "2026-10-29T17:30:37Z"
lastmod: "2026-10-29T20:17:37Z"
type: advisory
claim_state: <nil>
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:langflow_oss:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:langflow:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0 through 1.12.4)
  - Langflow OSS (1.0.0 through 1.12.8)
  - Langflow OSS (1.0.0 - 1.12.3)
  - Langflow OSS (1.0.0 through 1.12.3)
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
  - id: CVE-2026-101288
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-93680
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-104317
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-103092
    cvss: 8.5
    kev_status: "false"
  - id: CVE-2026-104324
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-104328
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-107326
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110196
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-110244
    kev_status: unknown
  - id: CVE-2026-110193
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107328
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107327
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110186
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93680
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101288
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103092
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104317
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104324
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104328
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107326
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110193
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110196
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110244
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Langflow OSS installations
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies affected versions 1.0.0 through 1.12.4
  hunt_leads:
    - lead: Monitor application access logs for directory traversal patterns such as ../ sequences
      technique_id: T1083
      data_needed:
        - Web application access logs (cs-uri-stem, cs-uri-query)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-110244 involves improper limitation of a pathname to a restricted directory
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest secure version of Langflow OSS
      owner: IT Operations
      addresses: CVE-2026-110244
      evidence: Vulnerability affects versions 1.0.0 through 1.12.4
updates:
  - at: "2026-10-29T20:17:28Z"
    level: L2
    summary: added CVE-2026-104324 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104324
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104328
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110193
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110196
  - at: "2026-10-29T20:17:37Z"
    level: L2
    summary: added coverage for Langflow OSS (1.0.0 through 1.12.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-110244
---

IBM Langflow OSS versions 1.0.0 through 1.12.4 allow a remote authenticated attacker to execute arbitrary code. This vulnerability is caused by improper neutralization of code in eval/exec.
