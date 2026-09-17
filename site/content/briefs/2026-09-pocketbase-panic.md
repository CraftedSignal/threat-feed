---
title: Denial of Service via Unhandled Panics in PocketBase Worker Goroutines
slug: 2026-09-pocketbase-panic
description: PocketBase is susceptible to a denial-of-service vulnerability (CVE-2026-82410) where unhandled panics in internal worker goroutines trigger unexpected server process termination.
date: "2026-09-17T19:14:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:pocketbase:pocketbase:*:*:*:*:*:*:*:*
vendors:
  - PocketBase
products:
  - PocketBase (< 0.22.48, >= 0.23.0, < 0.39.7)
cves:
  - id: CVE-2026-82410
references:
  - https://github.com/advisories/GHSA-84vh-m24q-wjjx
  - https://github.com/pocketbase/pocketbase/releases/tag/v0.39.7
  - https://github.com/pocketbase/pocketbase/releases/tag/v0.22.48
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-82410
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade PocketBase to v0.39.7 or v0.22.48
      owner: IT Operations
      addresses: CVE-2026-82410
      evidence: Source explicitly recommends upgrading to v0.39.7 or v0.22.48.
---

PocketBase, a Go-based backend-as-a-service platform, contains a vulnerability where internal child or worker goroutines do not properly handle panics. While the application's request-handling middleware includes standard panic recovery, internal background processes were previously exposed. If an attacker identifies a condition that triggers a panic within these worker functions, the resulting uncaught exception causes the entire server process to crash, leading to a denial-of-service (DoS) condition. This issue was addressed by introducing a `routine.SafeWrap(f)` helper function across all internal worker processes to intercept and recover from panics, converting them into manageable errors. The vulnerability is tracked as CVE-2026-82410 and affects multiple version branches. Administrators are urged to update to the latest patched releases to restore process stability.

## Impact

Successful exploitation results in a persistent denial-of-service, as the entire PocketBase server process terminates upon the occurrence of a triggered panic. This impacts availability for all services hosted on the instance. The issue affects users running versions prior to v0.22.48 and versions between v0.23.0 and v0.39.7.

## Recommendation

Prioritized actions for administrators:

* Patch PocketBase to version v0.39.7 or v0.22.48 immediately to integrate the `routine.SafeWrap` error handling for all worker goroutines.
* Audit server logs for unexpected process crashes or Go runtime panic stacks that coincide with specific user-initiated API requests or background tasks.
* Monitor service availability metrics for frequent restarts of the PocketBase process, which may indicate an ongoing attempt to exploit CVE-2026-82410.
