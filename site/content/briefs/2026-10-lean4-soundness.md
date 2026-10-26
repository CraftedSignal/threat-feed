---
brief_id: brief-2026-10-26-lean4-soundness
event_id: brief-2026-10-26-lean4-soundness
revision: 1
activity_at: "2026-10-26T02:22:56Z"
title: 'Lean 4: Kernel soundness vulnerability via nested inductive projections (CVE-2026-72844)'
slug: 2026-10-lean4-soundness
description: A soundness vulnerability in the Lean 4 kernel allows the construction of false mathematical proofs due to improper validation of structure projections and insufficient type-checking in the inductive definition process.
date: "2026-10-26T02:22:56Z"
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
  validation_status: No detection rules generated due to lack of log-observable malicious behavior; relies on internal system integrity checks.
cpes:
  - cpe:2.3:a:leanprover:lean:4:*:*:*:*:*:*:*
tags:
  - vulnerability
  - formal-verification
  - logic-soundness
vendors:
  - Lean
products:
  - Lean 4
cves:
  - id: CVE-2026-72844
    cvss: 6.3
    epss: 0.00176
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/379
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - CTI
  immediate_actions:
    - action: Inventory all production and research instances of Lean 4
      owner: Detection Engineering
      due: 48h
      evidence: Vulnerability affects core kernel logic
  enrichment_needed:
    - item: Patch release information for CVE-2026-72844
      owner: CTI
      reason: Necessary for remediation
      evidence: Vendor patch not yet announced
  mitigation_plan:
    - priority: immediate
      action: Monitor Lean repository for security updates and kernel patches
      owner: Detection Engineering
      addresses: CVE-2026-72844
      evidence: Source notes soundness bug in kernel code
---

A soundness vulnerability in the Lean 4 kernel (CVE-2026-72844) enables the construction of checked proofs of 'False' (e.g., 0 = 1). The flaw stems from two primary issues: the kernel fails to verify that the structure named in a projection expression matches the type of the value being projected, and the `environment::add_inductive` function in `src/kernel/inductive.cpp` fails to perform necessary type-checking for nested definitions. This compromise undermines the foundational logical guarantees of the theorem prover. No further update has been provided regarding fixed versions or mitigation timelines beyond the initial disclosure.

## Impact
This vulnerability allows for the creation of arbitrary proofs of logically false propositions within the Lean 4 environment. It does not require the use of explicit axioms, the `sorry` keyword, `unsafeCast` operations, or the modification of `.olean` files, allowing the exploit to bypass standard verification checks.

## Recommendation
- Inventory environments utilizing Lean 4 for formal verification or critical logical proofs.
- Monitor the official Lean 4 repository and the `oss-security` mailing list for the release of security patches or official mitigation guidance.
- Review critical proof developments that depend on the integrity of the Lean 4 kernel; consider re-verifying proofs using patched versions once updates are available.
