---
brief_id: brief-2026-11-03-surrealdb-uaf
event_id: brief-2026-11-03-surrealdb-uaf
revision: 1
activity_at: "2026-11-03T15:59:43Z"
title: 'SurrealDB: Use-after-free in surrealdb-core (CVE-2026-121417)'
slug: 2026-11-surrealdb-uaf
description: SurrealDB versions prior to 3.3.0 are vulnerable to a use-after-free condition in the KV backend that can be triggered by Rust embedders that leak dispatched futures.
date: "2026-11-03T15:59:43Z"
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
  validation_status: Source information is complete for the CVE disclosure.
cpes:
  - cpe:2.3:a:surrealdb:surrealdb:*:*:*:*:*:*:*:*
vendors:
  - SurrealDB
products:
  - surrealdb-core (< 3.3.0)
cves:
  - id: CVE-2026-121417
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121417
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  hunt_leads:
    - lead: Monitor for unexpected process terminations or segmentation faults in the SurrealDB service
      data_needed:
        - Application logs
        - System crash logs
        - SIGSEGV or SIGABRT signals in process monitoring
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Rust embedders that leak a dispatched future... cause pool workers to read and write freed memory, risking crashes
  mitigation_plan:
    - priority: immediate
      action: Upgrade SurrealDB to version 3.3.0 or later
      owner: IT Operations
      addresses: CVE-2026-121417
      evidence: SurrealDB before 3.3.0 contains a use-after-free vulnerability in surrealdb-core KV backends
---

SurrealDB versions before 3.3.0 contain a use-after-free vulnerability in the surrealdb-core KV backends. The flaw occurs when borrowed transaction state is passed into affinitypool::spawn_local closures that rely on future Drop for safety. If a Rust embedder leaks a dispatched future, such as through the use of `mem::forget`, the pool worker may access memory that has already been freed, leading to crashes or memory corruption.

## Impact
An attacker or a malformed application can induce memory corruption or cause the SurrealDB process to crash, resulting in a potential denial-of-service or memory instability.

## Recommendation
- Upgrade SurrealDB to version 3.3.0 or later to include the fix for CVE-2026-121417.
- Review custom Rust integrations or embedders that interact with the surrealdb-core library to ensure that futures are not improperly leaked or that the transaction lifecycle is strictly managed.
