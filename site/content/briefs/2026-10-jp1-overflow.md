---
brief_id: brief-2026-10-27-jp1-overflow
event_id: brief-2026-10-27-jp1-overflow
revision: 3
activity_at: "2026-10-29T22:24:10Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:03:29Z"
    checksum: sha256:6d70f9eb76674fe82082458943949c50d25fc477fa8203adb244ec88eff4decb
    summary: new product
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - lastmod
      - qa_status
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76936
  - revision: 3
    at: "2026-10-29T22:24:10Z"
    checksum: sha256:7ffad643bcbd8150c105ade33236cf1a87aaf79bb110c0c3070864ff2ecec7c8
    summary: added CVE-2026-76936 +1
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76937
title: 'JP1/Automatic Job Management System 3: Stack-based buffer overflow (CVE-2026-76932)'
slug: 2026-10-jp1-overflow
description: A stack-based buffer overflow vulnerability has been identified in JP1/Automatic Job Management System 3.
date: "2026-10-27T10:56:07Z"
lastmod: "2026-10-29T22:22:57Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:hitachi:jp1\/automatic_job_management_system_3:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - Hitachi
products:
  - JP1/Automatic Job Management System 3 - Manager (11-00 <= v < 13-50-31)
  - JP1/Automatic Job Management System 3 - Agent (11-00 <= v < 13-50-31)
  - JP1/Automatic Job Management System 3 - Manager (10-00 to <13-50-31)
  - JP1/Automatic Job Management System 3 - Manager (10-00 <= v < 13-50-31)
cves:
  - id: CVE-2026-76932
    cvss: 9.4
    epss: 0.00454
    kev_status: "false"
  - id: CVE-2026-76935
    cvss: 9.4
    epss: 0.00328
    kev_status: "false"
  - id: CVE-2026-76937
    cvss: 9.4
    epss: 0.00454
    kev_status: "false"
  - id: CVE-2026-76936
    cvss: 9.4
    epss: 0.00454
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76932
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76935
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76936
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76937
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and upgrade vulnerable versions of JP1/Automatic Job Management System 3 - Manager to 13-50-31
      owner: IT Operations
      due: 48h
      evidence: Vulnerability disclosure CVE-2026-76935
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 13-50-31 or later
      owner: IT Operations
      addresses: CVE-2026-76935
      evidence: NVD advisory for CVE-2026-76935
updates:
  - at: "2026-10-29T20:02:57Z"
    level: L2
    summary: added coverage for JP1/Automatic Job Management System 3 - Manager (10-00 to <13-50-31)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76935
  - at: "2026-10-29T20:02:58Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76936
  - at: "2026-10-29T22:22:57Z"
    level: L2
    summary: added CVE-2026-76936 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76937
---

CVE-2026-76932 identifies a stack-based buffer overflow vulnerability in JP1/Automatic Job Management System 3. 

Affected components and versions:
- JP1/Automatic Job Management System 3 - Manager: from 11-00 before 13-50-31
- JP1/Automatic Job Management System 3 - Agent: from 11-00 before 13-50-31

CVSS v3.1 Base Score: 9.4
