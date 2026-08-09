---
title: Linux Kernel posix-cpu-timers Use-After-Free Vulnerability
slug: 2026-08-linux-kernel-uaf
description: A use-after-free vulnerability in the Linux kernel posix-cpu-timers subsystem, identified as CVE-2026-64560, allows attackers to trigger kernel memory corruption via a race condition during non-leader thread exec() calls.
date: "2026-08-03T14:08:00Z"
lastmod: "2026-08-09T09:38:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - linux-kernel
  - cve
  - uaf
vendors:
  - Linux Foundation
products:
  - Linux Kernel
  - Android
affected_os:
  - Linux
  - Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability allows kernel memory corruption which is a prerequisite for local privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-64560
    cvss: 7.8
    epss: 0.0012
  - id: CVE-2026-64560
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64560
  - https://github.com/torvalds/linux/commit/920f893f735e92ba3a1cd9256899a186b161928d
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64560
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=F8E5B958-B5DC-57C1-9FA9-076BF3B70128
ioc_counts:
  url: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all Linux-based systems to the kernel versions identified in the brief.
      owner: IT Operations
      due: 72h
      evidence: Source provides specific fixed version numbers per branch.
  hunt_leads:
    - lead: Search for kernel panics/warnings related to UAF in logs.
      technique_id: T1068
      data_needed:
        - kernel_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC causes kernel warnings or panics in vulnerable kernels.
  mitigation_plan:
    - priority: immediate
      action: Patch kernel
      owner: IT Operations
      addresses: CVE-2026-64560
      evidence: Fix provided by upstream kernel.org.
  gaps:
    - Need to verify kernel versions across large enterprise fleets.
updates:
  - at: "2026-08-09T09:38:40Z"
    level: L1
    summary: new vendor
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64560
---

CVE-2026-64560 is a high-severity use-after-free (UAF) and race condition vulnerability within the Linux kernel's posix-cpu-timers subsystem. Introduced in kernel version 5.7, the flaw affects processes where a non-leader thread initiates an execve() system call, triggering a race condition between thread leader transition and timer deletion. Specifically, the function posix_cpu_timer_del() can incorrectly return early if it observes a null sighand pointer during a process transition, leaving a dangling reference to a k_itimer object within the process timer queue.

This vulnerability can lead to kernel crashes, panics, or potential security exploitation on Linux and Android systems. A public proof-of-concept (PoC) demonstrating the race condition is available on Sploitus, increasing the risk for unpatched systems. The issue has been addressed by Thomas Gleixner in the mainline kernel and backported to major stable branches, including 5.10, 5.15, 6.1, 6.6, 6.12, 6.18, and 7.1.

## Attack Chain

1. Attacker identifies a target system running an unpatched Linux kernel (v5.7 through 7.1).
2. Attacker compiles and executes the PoC trigger on the target device, which initiates multiple concurrent threads.
3. One thread (the timer thread) creates and arms a CLOCK_PROCESS_CPUTIME_ID timer.
4. Another thread (the exec thread) performs a fork() followed by a non-leader thread execve().
5. The race condition occurs when posix_cpu_timer_del() observes the old leader process while de_thread() is switching the task leader.
6. The timer remains enqueued in the process timer queue due to the incomplete deletion, leaving a dangling pointer.
7. Subsequent timer ticks (run_posix_cpu_timers) or add/delete operations access the dangling k_itimer object, resulting in a use-after-free read/write.
8. Kernel memory corruption occurs, leading to system instability or potential code execution depending on the kernel state.

## Impact

Successful exploitation of CVE-2026-64560 results in kernel memory corruption. While the public PoC is intended for research and trigger verification, it demonstrates the feasibility of triggering the UAF condition. On vulnerable systems, this can lead to system-wide denial-of-service (kernel panics), and in advanced scenarios, it provides a primitive that could be leveraged by local attackers for privilege escalation or sandbox escapes. Devices running Android with security patch levels (SPL) prior to August 2026 are likely affected.

## Recommendation

- Upgrade Linux kernel versions immediately to the patched releases (e.g., 5.10.262, 5.15.213, 6.1.180, 6.6.147, 6.12.100, 6.18.41, 7.1.5 or later).
- Use the provided PoC's check mode to verify the vulnerability status of test devices.
- Review kernel logs for KASAN, use-after-free, or BUG/WARNING entries related to 'timer' or 'posix' on sensitive infrastructure.
- Monitor for the execution of unauthorized custom binaries or build scripts that attempt to use NDK or local kernel compilation tools.
