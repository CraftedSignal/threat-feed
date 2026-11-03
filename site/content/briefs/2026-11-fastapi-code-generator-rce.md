---
brief_id: brief-2026-11-03-fastapi-code-generator-rce
event_id: brief-2026-11-03-fastapi-code-generator-rce
revision: 1
activity_at: "2026-11-03T21:27:38Z"
title: 'fastapi-code-generator: Import-time remote code execution (CVE-2026-63471)'
slug: 2026-11-fastapi-code-generator-rce
description: fastapi-code-generator versions prior to 0.8.1 contain a vulnerability that allows import-time remote code execution when processing malicious OpenAPI files by injecting arbitrary Python expressions into generated route decorators.
date: "2026-11-03T21:27:38Z"
lastmod: "2026-11-03T21:27:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:koxudaxi:fastapi_code_generator:*:*:*:*:*:*:*:*
tags:
  - rce
  - python
  - supply-chain
vendors:
  - koxudaxi
products:
  - fastapi-code-generator (< 0.8.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: Python
    evidence: An attacker-controlled or attacker-influenced operation summary can close the docstring and inject a valid Python expression statement into the handler body.
    confidence_band: high
cves:
  - id: CVE-2026-63471
    kev_status: "false"
  - id: CVE-2026-63470
    kev_status: "false"
references:
  - https://github.com/koxudaxi/fastapi-code-generator/security/advisories/GHSA-p2mm-64f6-gmpp
  - https://sploitus.com/exploit?id=CVE-2026-63471&utm_source=rss&utm_medium=rss
  - https://github.com/koxudaxi/fastapi-code-generator/security/advisories/GHSA-h667-4jj2-cgv4
  - https://github.com/koxudaxi/fastapi-code-generator/releases/tag/0.8.1
  - https://sploitus.com/exploit?id=CVE-2026-63470
  - https://sploitus.com/exploit?id=CVE-2026-63470&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade fastapi-code-generator to version 0.8.1 or later
      owner: IT Operations
      due: 24h
      evidence: This issue is fixed in version 0.8.1.
  hunt_leads:
    - lead: Identify projects utilizing fastapi-code-generator that process external or untrusted OpenAPI files
      technique_id: T1059.006
      data_needed:
        - Build pipeline logs
        - Source code repository analysis
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The generator inserts Operation.summary into a generated route-handler docstring without escaping embedded triple quotes.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to fastapi-code-generator 0.8.1
      owner: IT Operations
      addresses: CVE-2026-63470
      evidence: The vulnerability is fixed in version 0.8.1.
updates:
  - at: "2026-11-03T21:27:51Z"
    level: L2
    summary: added coverage for fastapi-code-generator (< 0.8.1)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-63470&utm_source=rss&utm_medium=rss
---
