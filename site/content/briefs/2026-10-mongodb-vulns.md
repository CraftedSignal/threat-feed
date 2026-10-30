---
brief_id: brief-2026-10-30-mongodb-vulns
event_id: brief-2026-10-30-mongodb-vulns
revision: 2
activity_at: "2026-10-30T21:33:35Z"
revision_history:
  - revision: 2
    at: "2026-10-30T21:33:35Z"
    checksum: sha256:8955d21a1cad707edfc0a7e8250b97b0cd98bdadd404c0f876f59f885c5351fa
    summary: added coverage for Laravel MongoDB (< 5.12.0)
    changed_fields:
      - action_plan
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/mongodb-security-advisory-av26-1107
title: 'MongoDB: Multiple vulnerabilities (CVE-2026-116641, CVE-2026-118510, CVE-2026-118581)'
slug: 2026-10-mongodb-vulns
description: Multiple vulnerabilities in MongoDB Database Tools, Java Driver, and Laravel MongoDB may lead to data integrity compromise, SQL injection, and security policy bypass.
date: "2026-10-30T21:19:42Z"
lastmod: "2026-10-30T21:33:01Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Patch versions validated against vendor release notes
cpes:
  - cpe:2.3:a:mongodb:database_tools:*:*:*:*:*:*:*:*
  - cpe:2.3:a:mongodb:java_driver:*:*:*:*:*:*:*:*
  - cpe:2.3:a:mongodb:laravel-mongodb:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - database
  - mongodb
  - informational
  - supply-chain
  - php
  - laravel
vendors:
  - MongoDB
products:
  - Database Tools (< 100.20.0)
  - Java Driver (< 5.14.0)
  - Laravel MongoDB (< 5.12.0)
cves:
  - id: CVE-2026-116641
    cvss: 6.8
    epss: 0.00144
    kev_status: "false"
  - id: CVE-2026-118510
    kev_status: unknown
  - id: CVE-2026-118581
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1430/
  - https://github.com/mongodb/laravel-mongodb/releases/tag/5.12.0
  - https://www.mongodb.com/docs/database-tools/release-notes/dbtools-100.20.0-changelog/
  - https://github.com/mongodb/mongo-java-driver/releases/tag/r5.14.0
  - https://www.cve.org/CVERecord?id=CVE-2026-116641
  - https://www.cve.org/CVERecord?id=CVE-2026-118510
  - https://www.cve.org/CVERecord?id=CVE-2026-118581
  - https://cyber.gc.ca/en/alerts-advisories/mongodb-security-advisory-av26-1107
  - https://jira.mongodb.org/browse/PHPLARA-148
  - https://www.mongodb.com/resources/products/alerts
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected MongoDB products to specified versions
      owner: IT Operations
      due: 48h
      evidence: Vendor security bulletins for Database Tools, Java Driver, and Laravel MongoDB
  hunt_leads:
    - lead: Search application logs for unexpected SQL syntax or SQLi patterns targeting MongoDB connections
      data_needed:
        - Application logs
        - Database proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerabilities allow SQL injection (SQLi)
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Database Tools 100.20.0, Java Driver r5.14.0, and Laravel MongoDB 5.12.0
      owner: IT Operations
      addresses: CVE-2026-116641, CVE-2026-118510, CVE-2026-118581
      evidence: Vendor security bulletins
    - priority: immediate
      action: Upgrade Laravel MongoDB to version 5.12.0 or later.
      owner: IT Operations
      addresses: Laravel MongoDB (< 5.12.0)
      evidence: 'As of October 28, 2026, MongoDB is affected by vulnerabilities in the following product: Laravel MongoDB prior to 5.12.0.'
updates:
  - at: "2026-10-30T21:33:01Z"
    level: L1
    summary: added coverage for Laravel MongoDB (< 5.12.0)
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/mongodb-security-advisory-av26-1107
---

Multiple vulnerabilities have been identified across several MongoDB components. These flaws may allow an attacker to compromise data integrity, perform SQL injection (SQLi), and bypass established security policies. The affected products include MongoDB Database Tools, Java Driver, and Laravel MongoDB. Users and administrators are advised to apply the patches provided in the referenced vendor security bulletins.

## Impact

Successful exploitation may result in unauthorized data modification, injection of malicious SQL commands, or bypassing intended security controls within the affected MongoDB environments.

## Recommendation

- Inventory all systems running MongoDB Database Tools, MongoDB Java Driver, or the Laravel MongoDB integration.
- Upgrade MongoDB Database Tools to version 100.20.0 or later.
- Upgrade MongoDB Java Driver to version r5.14.0 or later.
- Upgrade Laravel MongoDB to version 5.12.0 or later.
- Review application logs for anomalous SQL queries or unauthorized access patterns following the upgrade.
