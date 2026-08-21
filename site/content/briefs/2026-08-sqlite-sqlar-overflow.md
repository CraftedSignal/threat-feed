---
title: Heap Buffer Overflow in SQLite SQLAR Extension (CVE-2026-39113)
slug: 2026-08-sqlite-sqlar-overflow
description: A heap buffer overflow in the SQLite SQLAR extension (CVE-2026-39113) occurs when an attacker triggers sqlar_uncompress with a 64-bit size value that gets truncated during memory allocation, leading to heap corruption and potential denial of service.
date: "2026-08-21T12:36:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sqlite
  - sqlar
  - heap-buffer-overflow
  - denial-of-service
vendors:
  - SQLite
products:
  - SQLite (custom builds 2026-03-11 to 2026-04-01)
affected_os:
  - Ubuntu 24.04
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: AddressSanitizer observed a heap-buffer-overflow followed by process termination, establishing native heap corruption and denial of service.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=A820751A-E413-589A-97E0-4BAD8D4D0CB3
  - https://github.com/sqlite/sqlite/commit/169f68ed88b34cb68f720191c64c058f2ccec508
  - https://github.com/sqlite/sqlite/commit/34e139d3a306fcc0eeaf29de69783a311d48356b
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all custom-built software using SQLite to identify affected versions.
      owner: Application Security
      due: 72h
      evidence: The affected scope is source snapshots and custom builds from 169f68e through the parent of 34e139d.
  mitigation_plan:
    - priority: medium_term
      action: Upgrade custom SQLite builds to version 3.53.0 or later.
      owner: IT Operations
      addresses: CVE-2026-39113
      evidence: The corrected code is present in official SQLite 3.53.0.
---

CVE-2026-39113 is a memory-safety vulnerability in the optional SQLAR extension (`ext/misc/sqlar.c`) of the SQLite library. The issue stems from a type-mismatch introduced in a March 2026 commit, where a 64-bit size value (`sz`) is retrieved using `sqlite3_value_int64()` but passed to `sqlite3_malloc()` (which expects a 32-bit `int` on many platforms) for buffer allocation. Meanwhile, the zlib `uncompress()` function retains the full 64-bit size, causing the library to allocate an insufficient buffer and perform an out-of-bounds heap write during decompression.

The vulnerability affects custom builds and source snapshots derived from the Git commit `169f68e` (2026-03-11) through the parent of `34e139d` (2026-04-01). Official releases 3.52.0 (pre-introduction) and 3.53.0 (contains the fix) are not affected. While researchers demonstrated heap corruption leading to process termination (denial of service), arbitrary code execution was not achieved. The flaw is only reachable in applications that explicitly load the SQLAR extension and permit untrusted input to the `sqlar_uncompress()` SQL function.

## Impact

The impact of this vulnerability is primarily focused on denial of service via process crashes. Because the flaw occurs within the host process memory space, exploitation results in immediate heap corruption detected by AddressSanitizer or standard memory management handlers. While theoretical primitives for heap exploitation exist, no remote code execution chain was demonstrated. Organizations utilizing custom-built SQLite binaries or development snapshots between March and April 2026 are at risk if they enable the SQLAR extension in internet-facing or multi-tenant applications.

## Recommendation

- Identify all custom-built SQLite binaries and source snapshots within the development environment to determine if they fall within the vulnerable commit range.
- Upgrade any affected custom builds to the official SQLite 3.53.0 release or later, which utilizes `sqlite3_malloc64()` to resolve the allocation-width mismatch.
- Audit applications that load the `sqlar.c` extension and implement strict input validation for the `SZ` argument in `sqlar_uncompress()` to ensure it does not exceed reasonable bounds.
- If the SQLAR extension is not business-critical, disable it in the application configuration to remove the attack vector entirely.
