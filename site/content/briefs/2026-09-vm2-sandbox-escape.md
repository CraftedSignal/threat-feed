---
title: Arbitrary Memory Allocation Vulnerability in vm2
slug: 2026-09-vm2-sandbox-escape
description: The vm2 sandbox library prior to version 3.11.6 fails to enforce memory allocation limits on V8 intrinsics, allowing attackers to exhaust host process memory via arbitrary buffer allocation.
date: "2026-09-17T15:59:34Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - sandbox-escape
  - javascript
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can bypass the buffer allocation cap by using these V8 intrinsics to exhaust host process memory and trigger out-of-memory conditions.
    confidence_band: high
cves:
  - id: CVE-2026-92961
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92961
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  mitigation_plan:
    - priority: immediate
      action: Update vm2 to version 3.11.6 or later
      owner: Development
      addresses: CVE-2026-92961
      evidence: vm2 before 3.11.6 fails to enforce bufferAllocLimit
---

The vm2 JavaScript sandbox library, in versions prior to 3.11.6, contains a security vulnerability where the `bufferAllocLimit` is not correctly enforced on specific V8 intrinsics. Attackers can leverage the `ArrayBuffer`, `SharedArrayBuffer`, and `TypedArray` constructors to bypass predefined memory allocation caps within the sandbox. By invoking these constructors, an attacker can trigger arbitrary memory allocation on the underlying host process. This can lead to rapid exhaustion of host resources, resulting in an out-of-memory (OOM) condition and a subsequent denial-of-service for the application hosting the sandbox. This vulnerability is critical for environments that rely on vm2 to isolate untrusted code execution, as it effectively nullifies the library's resource management constraints.

## Impact

Successful exploitation allows an attacker to bypass security constraints and induce a denial-of-service by crashing the host process. This targets any Node.js application utilizing vm2 as a security boundary for processing user-supplied scripts or templates. The resulting OOM condition can lead to instability or complete unavailability of the dependent service.

## Recommendation

Update all instances of the vm2 package to version 3.11.6 or later to enforce the `bufferAllocLimit` across all V8 intrinsic constructors.
