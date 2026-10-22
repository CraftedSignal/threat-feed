---
brief_id: brief-2026-10-22-hapi-fhir-vulnerabilities
event_id: brief-2026-10-22-hapi-fhir-vulnerabilities
revision: 1
activity_at: "2026-10-22T23:52:41Z"
title: 'HAPI FHIR: Cross-tenant partition override and authorization bypasses (CVE-2026-113873, CVE-2026-113874, CVE-2026-113875, CVE-2026-113876)'
slug: 2026-10-hapi-fhir-vulnerabilities
description: Multiple vulnerabilities in HAPI FHIR version 8.10.0 allow for cross-tenant partition override, authorization bypasses, and heap exhaustion via gzip compression, potentially exposing patient data in multi-tenant environments.
date: "2026-10-22T23:52:41Z"
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
tags:
  - webserver
  - vulnerability
  - fhir
  - java
products:
  - HAPI FHIR (8.10.0)
cves:
  - id: CVE-2026-113873
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-113874
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-113875
    cvss: 3.1
    kev_status: "false"
  - id: CVE-2026-113876
    cvss: 4.3
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/336
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory HAPI FHIR deployments version 8.10.0 and prepare for patching.
      owner: IT Operations
      due: 48h
      evidence: Vulnerabilities reproduced on upstream HAPI FHIR 8.10.0.
  mitigation_plan:
    - priority: immediate
      action: Update HAPI FHIR to the latest patched version once released.
      owner: IT Operations
      addresses: CVE-2026-113873, CVE-2026-113874, CVE-2026-113875, CVE-2026-113876
      evidence: Source confirms 8.10.0 is the vulnerable version.
---

Four vulnerabilities (CVE-2026-113873, CVE-2026-113874, CVE-2026-113875, CVE-2026-113876) have been identified in HAPI FHIR version 8.10.0, an open-source Java implementation of the HL7 FHIR standard. These vulnerabilities allow an authenticated user to override tenant partitions, bypass authorization controls, or induce heap exhaustion through crafted gzip payloads. The flaws enable unauthorized read or write access to data residing in partitions belonging to other tenants.

## Impact
Successful exploitation allows unauthorized cross-tenant data access, leading to a compromise of data isolation. An attacker with legitimate access to one tenant could potentially read or manipulate records within another tenant partition.

## Recommendation
- Inventory all internal and external-facing instances of HAPI FHIR to identify deployments running version 8.10.0.
- Prioritize patching or updating HAPI FHIR instances to the secure version provided by the upstream maintainers as soon as it becomes available.
- Review access logs for abnormal cross-partition requests if HAPI FHIR multi-tenancy is in active use.
- Restrict access to FHIR API endpoints and implement robust input validation and rate limiting to mitigate potential DoS vectors such as heap exhaustion.
