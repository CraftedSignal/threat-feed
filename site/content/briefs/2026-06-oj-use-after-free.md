---
title: 'Oj: Use-After-Free in Oj::Doc Iterators via Reentrant Close'
slug: 2026-06-oj-use-after-free
description: A heap use-after-free vulnerability (CVE-2026-54897) exists in `Oj::Doc` iterators (`each_value`, `each_child`, `each_leaf`) in the `oj` Ruby gem, allowing an attacker to cause application crashes or unpredictable behavior when a Ruby block yielded during iteration reentrantly calls `doc.close` or `d.close`.
date: "2026-06-19T19:56:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ruby
  - use-after-free
  - library-vulnerability
  - dos
vendors:
  - Oj
products:
  - oj gem (< 3.17.2)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-9ppp-w3g4-fh4q
rules:
  - title: Detects Ruby Process Access Violation (Windows)
    description: Detects CVE-2026-54897 potential exploitation — Abnormal termination of Ruby processes due to an access violation (0xc0000005), which can be an outcome of a use-after-free vulnerability or other memory corruption issues in the `oj` gem or other Ruby components.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - application
      - windows
  - title: Detects Ruby Process Segmentation Fault (Linux)
    description: Detects CVE-2026-54897 potential exploitation — Kernel messages indicating a segmentation fault (segfault) involving a Ruby process, which can be a symptom of a use-after-free vulnerability or other memory corruption issues in the `oj` gem or other Ruby components.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - system
      - linux
rules_count: 2
---

A critical heap use-after-free vulnerability, identified as CVE-2026-54897, affects the `Oj::Doc` iterators within the `oj` Ruby gem. Specifically, the `each_value`, `each_child`, and `each_leaf` methods are vulnerable. The issue arises when a Ruby block, executed during the iteration process, makes a reentrant call to `doc.close` or `d.close` on the document or one of its child nodes. This premature closing operation frees the associated heap memory while the underlying C iterator in `ext/oj/fast.c` is still active. Upon returning from the Ruby block, the C code attempts to access memory that has already been deallocated, leading to a use-after-free condition. This vulnerability, present in all `oj` gem versions utilizing `ext/oj/fast.c` (confirmed up to v3.17.1), can be triggered from pure Ruby code and results in application instability, crashes, or potential arbitrary code execution. Organizations running Ruby applications that parse JSON via the `oj` gem are at risk.

## Attack Chain

1. A Ruby application integrates and uses the `oj` gem for JSON data processing.
2. The application opens a JSON document for parsing using the `Oj::Doc.open` method.
3. The application initiates an iteration over the document's elements using a vulnerable iterator method such as `each_value`, `each_child`, or `each_leaf`, providing a Ruby block for processing.
4. During the execution of the yielded Ruby block, a call is inadvertently made to `doc.close` or `d.close` on the `Oj::Doc` instance or one of its child nodes.
5. This `close` operation triggers the `ruby_sized_xfree` function within the `ext/oj/fast.c` source, leading to the premature deallocation of the underlying heap memory buffer associated with the `Oj::Doc` object.
6. Control returns from the Ruby block to the original C iterator function in `ext/oj/fast.c` (e.g., `doc_each_child`).
7. The C iterator attempts to access or dereference pointers (like `cur->next`) that point to the heap memory region which was previously freed in step 5.
8. This access to deallocated memory results in a use-after-free condition, manifesting as application crashes, segmentation faults, or unpredictable program behavior.

## Impact

The primary impact of CVE-2026-54897 is application instability and denial-of-service via crashing. Applications utilizing the vulnerable `oj` gem can be forced to terminate unexpectedly, leading to service disruption. Depending on the memory layout and the specific memory contents at the time of the use-after-free, this vulnerability could potentially be exploited for arbitrary code execution, though this has not been specifically detailed in the advisory. This could compromise the integrity and confidentiality of data processed by the Ruby application. Any Ruby application that handles untrusted JSON input and uses the vulnerable `oj` gem iterations is at risk.

## Recommendation

*   Upgrade the `oj` gem to version 3.17.2 or later immediately to patch CVE-2026-54897.
*   Review application code for instances where `doc.close` or `d.close` might be called reentrantly within `Oj::Doc` iterator blocks, as described in the overview.
*   Deploy the `Detects Ruby Process Access Violation (Windows)` Sigma rule to monitor for unusual crashes in Ruby applications.
*   Deploy the `Detects Ruby Process Segmentation Fault (Linux)` Sigma rule to monitor for crashes in Ruby applications on Linux systems.
