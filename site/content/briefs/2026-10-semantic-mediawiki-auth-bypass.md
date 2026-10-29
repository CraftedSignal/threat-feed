---
brief_id: brief-2026-10-27-semantic-mediawiki-auth-bypass
event_id: brief-2026-10-27-semantic-mediawiki-auth-bypass
revision: 2
activity_at: "2026-10-29T20:15:56Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:9f754ceeb4938c95516d41c6f413b8bdddc708a1ff171a632547fda6a66d1ae2
    summary: added coverage for Semantic MediaWiki (3.0.0-7.2.x)
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116890
title: 'Semantic MediaWiki: Missing authorization in smwtask API (CVE-2026-116873)'
slug: 2026-10-semantic-mediawiki-auth-bypass
description: Semantic MediaWiki from 7.3.0 before 7.3.1 contains a missing authorization vulnerability in the smwtask API module that allows unauthenticated attackers to run queued jobs and force store updates.
date: "2026-10-27T11:46:27Z"
lastmod: "2026-10-29T20:13:38Z"
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
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:semantic_mediawiki:semantic_mediawiki:*:*:*:*:*:*:*:*
  - cpe:2.3:a:semantic-mediawiki:semantic-mediawiki:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-application
  - cve
  - privilege-escalation
  - cms-security
  - vulnerability
  - authentication-bypass
vendors:
  - Semantic MediaWiki
products:
  - Semantic MediaWiki (7.3.0 before 7.3.1)
  - Semantic MediaWiki (>= 2.5.0, < 7.3.1)
  - Semantic MediaWiki (2.5.0 <= version < 7.3.1)
  - Semantic MediaWiki (3.0.0-7.2.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The vulnerability allows anonymous attackers to force quadratic computation... exhausting PHP CPU, memory, and database connections.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows users with 'editor' privileges to apply indefinite edit and move restrictions to pages by adding an 'Is edit protected' annotation.
    confidence_band: high
cves:
  - id: CVE-2026-116873
    cvss: 7.3
    kev_status: "false"
  - id: CVE-2026-116878
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-116876
    cvss: 7.1
    epss: 0.00235
    kev_status: "false"
  - id: CVE-2026-116890
    cvss: 7.3
    epss: 0.00191
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116873
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116878
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116876
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116890
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
    - action: Upgrade Semantic MediaWiki to version 7.3.1 or later
      owner: IT Operations
      due: 48h
      evidence: Source states versions 2.5.0 through 7.3.0 are susceptible.
    - action: Upgrade Semantic MediaWiki to 7.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: Semantic MediaWiki from 3.0.0 before 7.3.0 contains a missing authorization vulnerability
  hunt_leads:
    - lead: Identify pages where 'Is edit protected' has been applied by non-administrative users
      technique_id: T1068
      data_needed:
        - MediaWiki edit history logs
        - Semantic MediaWiki annotation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability allows ordinary editors to apply indefinite edit restrictions via the annotation.
    - lead: Identify unauthorized access to the smwtask API module
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can use the public anonymous CSRF token to read internal store statistics, enqueue jobs like smw.entityIdDisposer
  mitigation_plan:
    - priority: immediate
      action: Block or rate-limit requests to 'Special:PropertyLabelSimilarity' with 'limit=0'
      owner: SOC
      addresses: CVE-2026-116878
      evidence: Source identifies this parameter as the vector for resource consumption.
    - priority: immediate
      action: Disable $smwgEditProtectionRight in Semantic MediaWiki configuration
      owner: IT Operations
      addresses: CVE-2026-116876
      evidence: Disabling this feature prevents the vulnerable updater from executing.
    - priority: immediate
      action: Apply patch to version 7.3.0
      owner: IT Operations
      addresses: CVE-2026-116890
      evidence: Semantic MediaWiki from 3.0.0 before 7.3.0 contains a missing authorization vulnerability
updates:
  - at: "2026-10-27T11:46:39Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-116878 Exploitation - Resource Exhaustion via PropertyLabelSimilarity'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116878
  - at: "2026-10-29T20:13:33Z"
    level: L2
    summary: added coverage for Semantic MediaWiki (2.5.0 <= version < 7.3.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116876
  - at: "2026-10-29T20:13:38Z"
    level: L2
    summary: added coverage for Semantic MediaWiki (3.0.0-7.2.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116890
---

Semantic MediaWiki from 7.3.0 before 7.3.1 contains a missing authorization vulnerability in the `smwtask` API module. This allows unauthenticated attackers to use the public anonymous CSRF token with `run-joblist` to execute arbitrary job types in unbounded counts, or invoke `update` on sysop-protected pages. These actions can result in the leakage of page titles and resource exhaustion.
