---
brief_id: brief-2026-10-27-semantic-mediawiki-auth-bypass
event_id: brief-2026-10-27-semantic-mediawiki-auth-bypass
revision: 1
activity_at: "2026-10-27T11:46:27Z"
title: 'Semantic MediaWiki: Missing authorization in smwtask API (CVE-2026-116873)'
slug: 2026-10-semantic-mediawiki-auth-bypass
description: Semantic MediaWiki from 7.3.0 before 7.3.1 contains a missing authorization vulnerability in the smwtask API module that allows unauthenticated attackers to run queued jobs and force store updates.
date: "2026-10-27T11:46:27Z"
lastmod: "2026-10-27T11:46:39Z"
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:semantic_mediawiki:semantic_mediawiki:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-application
  - cve
vendors:
  - Semantic MediaWiki
products:
  - Semantic MediaWiki (7.3.0 before 7.3.1)
  - Semantic MediaWiki (>= 2.5.0, < 7.3.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The vulnerability allows anonymous attackers to force quadratic computation... exhausting PHP CPU, memory, and database connections.
    confidence_band: high
cves:
  - id: CVE-2026-116873
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-116878
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116873
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116878
rules:
  - title: Detects CVE-2026-116878 Exploitation - Resource Exhaustion via PropertyLabelSimilarity
    description: Detects attempts to trigger resource exhaustion in Semantic MediaWiki by targeting the Special:PropertyLabelSimilarity endpoint with a limit parameter of zero.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Semantic MediaWiki to version 7.3.1
      owner: IT Operations
      due: 48h
      evidence: Source explicitly names 7.3.1 as the fix version.
  mitigation_plan:
    - priority: immediate
      action: Block or rate-limit requests to 'Special:PropertyLabelSimilarity' with 'limit=0'
      owner: SOC
      addresses: CVE-2026-116878
      evidence: Source identifies this parameter as the vector for resource consumption.
updates:
  - at: "2026-10-27T11:46:39Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-116878 Exploitation - Resource Exhaustion via PropertyLabelSimilarity'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116878
---

Semantic MediaWiki from 7.3.0 before 7.3.1 contains a missing authorization vulnerability in the `smwtask` API module. This allows unauthenticated attackers to use the public anonymous CSRF token with `run-joblist` to execute arbitrary job types in unbounded counts, or invoke `update` on sysop-protected pages. These actions can result in the leakage of page titles and resource exhaustion.
