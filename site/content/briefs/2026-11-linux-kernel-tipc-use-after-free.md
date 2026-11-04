---
brief_id: brief-2026-11-04-linux-kernel-tipc-use-after-free
event_id: brief-2026-11-04-linux-kernel-tipc-use-after-free
revision: 1
activity_at: "2026-11-04T02:27:39Z"
title: 'Linux Kernel: TIPC Subsystem Use-After-Free (CVE-2026-99246)'
slug: 2026-11-linux-kernel-tipc-use-after-free
description: A race condition in the Linux kernel TIPC subsystem allows a local attacker to trigger a use-after-free vulnerability via concurrent node reset trace events and bearer teardown, potentially leading to system instability or crashes.
date: "2026-11-04T02:27:39Z"
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
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
vendors:
  - Linux
products:
  - Linux Kernel (unspecified versions prior to fix)
cves:
  - id: CVE-2026-99246
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-99246
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  hunt_leads:
    - lead: Monitor for kernel crash logs or oops reports involving tipc_link_dump, tipc_node_dump, or tipc_node_reset_links
      data_needed:
        - dmesg
        - kernel logs
        - KASAN reports
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'KASAN reported: BUG: KASAN: slab-use-after-free in tipc_link_dump'
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for the Linux kernel provided by the distribution vendor to address CVE-2026-99246
      owner: IT Operations
      addresses: CVE-2026-99246
      evidence: The vulnerability is resolved by acquiring the node write lock during the trace event.
    - priority: short_term
      action: Identify and disable unused TIPC kernel modules to reduce attack surface
      owner: IT Operations
      addresses: Linux Kernel TIPC subsystem
      evidence: The vulnerability is located within the tipc_node_reset_links trace event and related TIPC handling logic.
---

The Linux kernel TIPC (Transparent Inter Process Communication) subsystem contains a use-after-free vulnerability (CVE-2026-99246) caused by improper locking during the `tipc_node_reset_links` trace event. The vulnerability arises because the trace event executes without holding the node lock, allowing a link to be freed by a concurrent bearer teardown process while the trace callback is attempting to dump the link. This race condition results in a memory corruption scenario as `tipc_link_dump()` dereferences a stale pointer.

## Impact

The vulnerability allows an unprivileged local attacker or a process with sufficient privileges to interact with the TIPC subsystem to trigger a use-after-free condition. This likely results in a kernel panic or system crash (Denial of Service). There is no confirmed evidence of remote exploitation or privilege escalation, though memory corruption bugs can occasionally be leveraged for such purposes in specialized environments.

## Recommendation

Update the Linux kernel to a version containing the fix for CVE-2026-99246. As the vulnerability requires specific race conditions within the TIPC subsystem, systems that do not utilize TIPC may reduce their attack surface by disabling the module (e.g., via `modprobe -r tipc` or blacklisting).
