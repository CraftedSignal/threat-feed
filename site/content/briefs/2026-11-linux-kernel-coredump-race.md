---
brief_id: brief-2026-11-05-linux-kernel-coredump-race
event_id: brief-2026-11-05-linux-kernel-coredump-race
revision: 1
activity_at: "2026-11-05T16:32:04Z"
title: 'Linux Kernel: Use-after-free in coredump_finish() (CVE-2026-99218)'
slug: 2026-11-linux-kernel-coredump-race
description: A vulnerability in the Linux kernel coredump implementation exists where coredump_finish() fails to maintain an RCU lock while releasing parked threads, leading to a potential use-after-free condition.
date: "2026-11-05T16:32:04Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:linux:kernel:*:*:*:*:*:*:*:*
vendors:
  - Linux
products:
  - Linux kernel
cves:
  - id: CVE-2026-99218
    cvss: 7
    epss: 0.00122
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-99218
---

In the Linux kernel, `coredump_finish()` releases parked threads without holding an RCU reference. If the process is preempted between clearing the task pointer and calling `wake_up_process()`, the target thread may exit and be freed. This results in a use-after-free condition when `try_to_wake_up()` attempts to acquire a `pi_lock` on the freed memory.

## Impact
This vulnerability may lead to kernel instability.
