---
brief_id: brief-2026-11-04-apache-openoffice-lfi
event_id: brief-2026-11-04-apache-openoffice-lfi
revision: 1
activity_at: "2026-11-04T06:25:56Z"
title: 'Apache OpenOffice: Local file inclusion in flat file database driver (CVE-2026-90627)'
slug: 2026-11-apache-openoffice-lfi
description: Apache OpenOffice versions through 4.1.16 contain a local file inclusion vulnerability in the flat file database driver that allows arbitrary file reads via crafted documents.
date: "2026-11-04T06:25:56Z"
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
cpes:
  - cpe:2.3:a:apache:openoffice:*:*:*:*:*:*:*:*
tags:
  - lfi
  - vulnerability
  - office-software
vendors:
  - Apache
products:
  - OpenOffice (<= 4.1.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: The flat file database driver in Apache Openoffice versions through 4.1.16 allows a crafted document to read the contents of any local file.
    confidence_band: high
cves:
  - id: CVE-2026-90627
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/502
  - https://openoffice.apache.org/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Apache OpenOffice to version 4.1.17
      owner: IT Operations
      due: 48h
      evidence: Users are recommended to upgrade to version 4.1.17, which fixes this issue.
  hunt_leads:
    - lead: Identify documents containing database references or suspicious external links in document metadata
      technique_id: T1204.002
      data_needed:
        - Document metadata analysis
        - File system access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves manipulation of SQL provider and flat file database references.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Apache OpenOffice 4.1.17
      owner: IT Operations
      addresses: CVE-2026-90627
      evidence: Users are recommended to upgrade to version 4.1.17, which fixes this issue.
---

A vulnerability exists in the flat file database driver within Apache OpenOffice versions through 4.1.16. This flaw allows a maliciously crafted document to read local files on the underlying system without user permission or interaction. Apache has released version 4.1.17 to remediate this issue.

## Impact
Successful exploitation allows for unauthorized reading of arbitrary files from the local filesystem with the privileges of the user running the Apache OpenOffice process.

## Recommendation
- Upgrade all instances of Apache OpenOffice to version 4.1.17 or later immediately.
- Inventory systems running Apache OpenOffice version 4.1.16 or earlier.
- Apply the principle of least privilege to the user accounts running Office software to limit the scope of potential file access in the event of document-based exploitation.
