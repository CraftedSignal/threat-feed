---
brief_id: brief-2026-11-22-mongodb-drivers
event_id: brief-2026-11-22-mongodb-drivers
revision: 2
activity_at: "2026-11-26T19:51:56Z"
revision_history:
  - revision: 2
    at: "2026-11-26T19:51:56Z"
    checksum: sha256:c74a9f54bcabc4fa2372d585af4aca2a2e0bd527bf0fa44be6210b5193cd0404
    summary: added CVE-2026-135145
    changed_fields:
      - affected_products
      - content
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - summary
      - title
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-135145
title: 'MongoDB PHP Driver: Authorization bypass in polymorphic relationship queries (CVE-2026-135145)'
slug: 2026-11-mongodb-drivers
description: The MongoDB PHP Driver contains an inconsistency in polymorphic relationship query resolution that can allow authenticated users to bypass access restrictions and perform unauthorized data operations.
date: "2026-11-22T15:33:54Z"
lastmod: "2026-11-26T19:49:42Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Content aligns with BSI advisory; further vendor-specific intelligence is required for operational remediation.
cpes:
  - cpe:2.3:a:mongodb:php_driver:4.1.0:*:*:*:*:*:*:*
vendors:
  - MongoDB
products:
  - MongoDB Drivers
  - PHP Driver
product_versions:
  - product: PHP Driver
    range: '>= 4.1.0, < 5.12.2'
cves:
  - id: CVE-2026-135145
    cvss: 8.1
    epss: 0.00553
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4701
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4819
  - https://nvd.nist.gov/vuln/detail/CVE-2026-135145
  - https://cveawg.mitre.org/api/cve/CVE-2026-135145
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit software inventory to identify applications using MongoDB drivers.
      owner: IT Operations
      due: 48h
      evidence: BSI advisory warns of vulnerabilities in MongoDB drivers.
  enrichment_needed:
    - item: CVE list and affected version matrix
      owner: CTI
      reason: The source lacks specific version numbers or CVE IDs necessary for surgical patching.
      evidence: BSI alert lacks specific versioning detail.
  hunt_leads:
    - lead: Inventory software dependencies for libraries associated with MongoDB drivers.
      data_needed:
        - Software Bill of Materials (SBOM)
        - Application dependency lists
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source identifies MongoDB drivers as the vulnerable component.
updates:
  - at: "2026-11-26T19:49:42Z"
    level: L2
    summary: added CVE-2026-135145
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-135145
---

## Overview
A vulnerability exists in the MongoDB PHP Driver, specifically within the polymorphic relationship query helper used in its integration for Laravel. The component resolves a record's type identifier inconsistently between the code that stores a relationship link and the code that searches for one. 

## Impact
An application that relies on a relationship-absence query to restrict which records a request may see or change can have that restriction silently fail. This allows a user with basic application privileges to read, modify, or remove records that the restriction was meant to cover. This issue affects data confidentiality and integrity with a CVSS v3.1 base score of 8.1.

## Recommendation
Upgrade the MongoDB PHP Driver to version 5.12.2 or later to address the vulnerability.
