---
brief_id: brief-2026-10-26-mongodb-vulnerabilities-866b95d6
event_id: brief-2026-10-26-mongodb-vulnerabilities-866b95d6
revision: 1
activity_at: "2026-10-26T22:20:52Z"
title: 'MongoDB: Multiple product vulnerabilities (CVE-2026-114643 et al.)'
slug: 2026-10-mongodb-vulnerabilities-866b95d6
description: Multiple vulnerabilities across MongoDB drivers and tools expose systems to arbitrary code execution, data integrity and confidentiality loss, denial of service, and injection attacks.
date: "2026-10-26T22:20:52Z"
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
  validation_status: Verified against ANSSI advisory and vendor Jira bulletins
tags:
  - vulnerability
  - mongodb
  - rce
  - injection
vendors:
  - MongoDB
products:
  - C Driver (< 2.5.7, < 1.30.14)
  - C# Driver (< 3.13.0)
  - Compass (< 1.53.1)
  - libmongocrypt (< 1.21.1)
cves:
  - id: CVE-2026-114643
    cvss: 5.4
    epss: 0.00372
    kev_status: "false"
  - id: CVE-2026-114644
    cvss: 5.9
    epss: 0.00481
    kev_status: "false"
  - id: CVE-2026-114645
    cvss: 5.2
    epss: 0.00166
    kev_status: "false"
  - id: CVE-2026-114646
    kev_status: unknown
  - id: CVE-2026-114647
    kev_status: unknown
  - id: CVE-2026-114648
    cvss: 7.6
    epss: 0.00321
    kev_status: "false"
  - id: CVE-2026-114649
    cvss: 6.8
    epss: 0.002
    kev_status: "false"
  - id: CVE-2026-114650
    kev_status: unknown
  - id: CVE-2026-114651
    kev_status: unknown
  - id: CVE-2026-114652
    kev_status: unknown
  - id: CVE-2026-114653
    kev_status: unknown
  - id: CVE-2026-114654
    kev_status: unknown
  - id: CVE-2026-114655
    kev_status: unknown
  - id: CVE-2026-115929
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1386/
  - https://jira.mongodb.org/browse/CDRIVER-6421
  - https://jira.mongodb.org/browse/CSHARP-6157
  - https://jira.mongodb.org/browse/CSHARP-6162
  - https://jira.mongodb.org/browse/CSHARP-6166
  - https://jira.mongodb.org/browse/CSHARP-6168
  - https://jira.mongodb.org/browse/CSHARP-6170
  - https://jira.mongodb.org/browse/CSHARP-6174
  - https://jira.mongodb.org/browse/CSHARP-6179
  - https://jira.mongodb.org/browse/CSHARP-6180
  - https://jira.mongodb.org/browse/CSHARP-6181
  - https://jira.mongodb.org/browse/CSHARP-6184
  - https://jira.mongodb.org/browse/CSHARP-6186
  - https://jira.mongodb.org/browse/MONGOCRYPT-963
  - https://github.com/mongodb-js/compass/releases/tag/v1.53.1
  - https://www.cve.org/CVERecord?id=CVE-2026-114643
  - https://www.cve.org/CVERecord?id=CVE-2026-114644
  - https://www.cve.org/CVERecord?id=CVE-2026-114645
  - https://www.cve.org/CVERecord?id=CVE-2026-114646
  - https://www.cve.org/CVERecord?id=CVE-2026-114647
  - https://www.cve.org/CVERecord?id=CVE-2026-114648
  - https://www.cve.org/CVERecord?id=CVE-2026-114649
  - https://www.cve.org/CVERecord?id=CVE-2026-114650
  - https://www.cve.org/CVERecord?id=CVE-2026-114651
  - https://www.cve.org/CVERecord?id=CVE-2026-114652
  - https://www.cve.org/CVERecord?id=CVE-2026-114653
  - https://www.cve.org/CVERecord?id=CVE-2026-114654
  - https://www.cve.org/CVERecord?id=CVE-2026-114655
  - https://www.cve.org/CVERecord?id=CVE-2026-115929
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory MongoDB drivers and Compass installations to identify vulnerable versions.
      owner: IT Operations
      due: 48h
      evidence: Affected products listed in ANSSI advisory
  mitigation_plan:
    - priority: immediate
      action: 'Upgrade to identified safe versions: C Driver 2.5.7/1.30.14, C# Driver 3.13.0, Compass 1.53.1, libmongocrypt 1.21.1.'
      owner: IT Operations
      addresses: All identified vulnerable MongoDB products
      evidence: Remediation guidance in ANSSI advisory
---

The French National Cybersecurity Agency (ANSSI) has reported multiple vulnerabilities affecting several MongoDB software products, including C and C# drivers, MongoDB Compass, and libmongocrypt. These flaws collectively enable attackers to achieve arbitrary code execution, unauthorized data access, data corruption, and various injection-based attacks. 

## Impact
The identified vulnerabilities can result in arbitrary code execution, compromise of data confidentiality and integrity, denial of service, CSRF, and SQL injection. The impact is significant for applications relying on affected MongoDB drivers or administrative tools like Compass.

## Recommendation
- Inventory all environments using MongoDB C Driver, C# Driver, MongoDB Compass, and libmongocrypt.
- Upgrade MongoDB C Driver to version 2.5.7 or higher, or 1.30.14 or higher, depending on the branch.
- Upgrade MongoDB C# Driver to version 3.13.0 or higher.
- Upgrade MongoDB Compass to version 1.53.1 or higher.
- Upgrade libmongocrypt to version 1.21.1 or higher.
- Refer to the individual MongoDB Jira issue trackers for each specific CVE for detailed remediation guidance provided by the vendor.
