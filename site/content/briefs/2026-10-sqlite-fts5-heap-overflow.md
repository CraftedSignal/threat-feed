---
brief_id: brief-2026-10-30-sqlite-fts5-heap-overflow
event_id: brief-2026-10-30-sqlite-fts5-heap-overflow
revision: 1
activity_at: "2026-10-30T15:30:25Z"
title: 'SQLite: Heap buffer overflow in FTS5 extension (CVE-2026-119373)'
slug: 2026-10-sqlite-fts5-heap-overflow
description: SQLite versions prior to 3.54.0, when compiled with FTS5, contain a heap buffer overflow vulnerability that allows local memory corruption or process crashes via crafted prefix MATCH queries.
date: "2026-10-30T15:30:25Z"
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
  validation_status: Source verified; no IOCs or specific TTP logs available for Sigma rule generation.
cpes:
  - cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*
vendors:
  - SQLite
products:
  - SQLite (< 3.54.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers who can populate a detail=none FTS5 table with negative rowids and run a prefix MATCH query can write past the allocation, corrupting heap memory and crashing the process.
    confidence_band: high
cves:
  - id: CVE-2026-119373
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119373
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Identify applications using FTS5 extension with input-driven table population
      technique_id: T1203
      data_needed:
        - Application dependency inventory
        - Database schema audits
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers who can populate a detail=none FTS5 table with negative rowids
  mitigation_plan:
    - priority: immediate
      action: Upgrade SQLite library to version 3.54.0 or later
      owner: IT Operations
      addresses: CVE-2026-119373
      evidence: SQLite before 3.54.0 built with FTS5 contains a heap buffer overflow
---

SQLite versions before 3.54.0, when the FTS5 full-text search extension is enabled, contain a heap buffer overflow in the fts5MergeRowidLists function. The vulnerability arises from an incorrect buffer size calculation when merging doclists where the detail level is set to 'none'. Successful exploitation requires an attacker to populate an FTS5 table with negative row identifiers and subsequently execute a prefix MATCH query. This condition triggers the buffer overflow, resulting in heap memory corruption or a process crash.

## Impact
Observed impact is limited to heap memory corruption and application process crashes. While heap-based overflows can sometimes lead to arbitrary code execution, this specific vulnerability is primarily documented as a crash/denial-of-service condition at this time.

## Recommendation
- Upgrade SQLite to version 3.54.0 or later to include the patch for CVE-2026-119373.
- Audit applications that utilize the SQLite FTS5 extension, particularly those that accept untrusted input for table creation or query construction, to determine if they are running a vulnerable version.
