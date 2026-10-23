---
brief_id: brief-2026-10-21-zephyr-rtos-race-condition
event_id: brief-2026-10-21-zephyr-rtos-race-condition
revision: 2
activity_at: "2026-10-23T22:05:51Z"
revision_history:
  - revision: 2
    at: "2026-10-23T22:05:51Z"
    checksum: sha256:04c797ddc965b4a5a5fcd4b914382c16164d2acc36d511766bb765b40060bf8b
    summary: added coverage for Zephyr RTOS
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-79979
title: 'Zephyr RTOS: Kernel wait queue race condition (CVE-2026-78118)'
slug: 2026-10-zephyr-rtos-race-condition
description: A race condition in the Zephyr RTOS scheduler wait queue management allows unprivileged user-mode threads to trigger out-of-bounds memory access or use-after-free in supervisor context by exploiting improper locking in SMP configurations.
date: "2026-10-21T19:59:18Z"
lastmod: "2026-10-23T22:04:52Z"
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
  validation_status: Checked against NVD details
cpes:
  - cpe:2.3:o:zephyrproject:zephyr:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - embedded
  - mctp
  - i2c
products:
  - Zephyr RTOS (< current patched versions)
  - Zephyr RTOS (with CONFIG_MCTP and CONFIG_MCTP_I2C_GPIO_TARGET enabled)
  - Zephyr RTOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Exploitation via system calls from unprivileged user-mode threads can lead to supervisor-mode memory corruption, scheduler state instability, or kernel crashes.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The dereference happens in the I2C target interrupt handler, so on any target that traps accesses to address 0 the result is a fatal exception and a device reset or halt
    confidence_band: high
cves:
  - id: CVE-2026-78118
    kev_status: unknown
  - id: CVE-2026-79979
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-79976
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78118
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79976
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79979
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Zephyr RTOS environment
      owner: IT Operations
      due: 72h
      evidence: Vulnerability requires kernel-level patch to secure wait queue access.
    - action: Patch Zephyr RTOS to include the fix for CVE-2026-79979
      owner: IT Operations
      due: 72h
      evidence: The fix switches the implementation to TLBI VAAE1{IS}, which matches every ASID and both global and non-global entries.
  hunt_leads:
    - lead: Monitor for unexpected kernel panics or reboots in multi-CPU Zephyr deployments
      technique_id: T1068
      data_needed:
        - Kernel crash logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation often results in kernel crashes.
    - lead: Monitor for anomalous memory access patterns or unexpected page fault handling by user-space threads that might indicate exploitation attempts under high memory pressure.
      technique_id: T1068
      data_needed:
        - Kernel-level instrumentation of page fault handling
        - Memory allocation/eviction logs
      priority: medium
      confidence: low
      disposition: hunt_now
      evidence: Exploitation requires an arm64 build with both CONFIG_USERSPACE and CONFIG_DEMAND_PAGING enabled.
  mitigation_plan:
    - priority: immediate
      action: Apply kernel patch to lock z_waitq_head usage
      owner: IT Operations
      addresses: CVE-2026-78118
      evidence: Source describes the fix as splitting z_waitq_head and locking the timer expiration handler.
    - priority: immediate
      action: Disable CONFIG_DEMAND_PAGING if not strictly required until the environment can be patched.
      owner: IT Operations
      addresses: CVE-2026-79979
      evidence: Exploitation requires an arm64 build with both CONFIG_USERSPACE and CONFIG_DEMAND_PAGING enabled.
updates:
  - at: "2026-10-21T19:59:24Z"
    level: L2
    summary: added coverage for Zephyr RTOS (with CONFIG_MCTP and CONFIG_MCTP_I2C_GPIO_TARGET enabled)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-79976
  - at: "2026-10-23T22:04:52Z"
    level: L2
    summary: added coverage for Zephyr RTOS
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-79979
---

A race condition exists in the Zephyr RTOS kernel due to improper locking of the thread wait queue in Symmetric Multiprocessing (SMP) environments. The z_waitq_head() helper function is called without holding the required _sched_spinlock, allowing for out-of-bounds access or use-after-free conditions when a timer expiration handler interacts with a thread wait queue simultaneously with a thread abortion. Exploitation via system calls from unprivileged user-mode threads can lead to supervisor-mode memory corruption, scheduler state instability, or kernel crashes. This vulnerability only affects multi-CPU builds (CONFIG_MP_MAX_NUM_CPUS > 1).

## Attack Chain
1. An unprivileged user-mode thread triggers an attempt to exploit the race condition via system calls.
2. The attacker uses k_thread_create() and k_thread_abort() to manipulate thread states in the wait queue.
3. Simultaneously, k_timer_start() and k_timer_status_sync() are utilized to trigger the z_timer_expiration_handler().
4. The handler calls z_waitq_head() without holding the _sched_spinlock.
5. A race window is opened where a competing thread is removed from the queue on a different CPU.
6. z_waitq_head() returns an invalid pointer (either a list sentinel or a pointer to a freed thread structure).
7. The kernel performs an out-of-bounds or use-after-free write via unpend_thread_no_timeout() and arch_thread_return_value_set().

## Impact
The primary observed outcome is a kernel crash (DoS). In controlled scenarios, exploitation leads to supervisor-mode memory corruption or scheduler state instability, which could potentially be leveraged for privilege escalation.

## Recommendation
- Update Zephyr RTOS projects to include the fix that enforces the use of z_waitq_head_locked() and encapsulates timer expiration logic within a single LOCK_SCHED_SPINLOCK region.
- Review kernel configurations to ensure that multi-CPU environments are managed with appropriate locking primitives as defined in the vendor security patch.
- Audit custom system call implementations for race conditions involving wait queue access.
