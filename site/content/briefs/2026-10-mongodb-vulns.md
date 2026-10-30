---
brief_id: brief-2026-10-30-mongodb-vulns
event_id: brief-2026-10-30-mongodb-vulns
revision: 1
activity_at: "2026-10-30T21:19:42Z"
title: 'MongoDB: Multiple vulnerabilities (CVE-2026-116641, CVE-2026-118510, CVE-2026-118581)'
slug: 2026-10-mongodb-vulns
description: Multiple vulnerabilities in MongoDB Database Tools, Java Driver, and Laravel MongoDB may lead to data integrity compromise, SQL injection, and security policy bypass.
date: "2026-10-30T21:19:42Z"
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
