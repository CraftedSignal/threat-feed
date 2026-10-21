---
brief_id: brief-2026-10-21-zephyr-rtos-race-condition
event_id: brief-2026-10-21-zephyr-rtos-race-condition
revision: 1
activity_at: "2026-10-21T19:59:18Z"
title: 'Zephyr RTOS: Kernel wait queue race condition (CVE-2026-78118)'
slug: 2026-10-zephyr-rtos-race-condition
description: A race condition in the Zephyr RTOS scheduler wait queue management allows unprivileged user-mode threads to trigger out-of-bounds memory access or use-after-free in supervisor context by exploiting improper locking in SMP configurations.
date: "2026-10-21T19:59:18Z"
lastmod: "2026-10-21T19:59:24Z"
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
tags:
  - vulnerability
  - embedded
  - mctp
  - i2c
products:
  - Zephyr RTOS (< current patched versions)
  - Zephyr RTOS (with CONFIG_MCTP and CONFIG_MCTP_I2C_GPIO_TARGET enabled)
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
  - id: CVE-2026-79976
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78118
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79976
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Zephyr RTOS environment
      owner: IT Operations
      due: 72h
      evidence: Vulnerability requires kernel-level patch to secure wait queue access.
  hunt_leads:
    - lead: Monitor for unexpected kernel panics or reboots in multi-CPU Zephyr deployments
      technique_id: T1068
      data_needed:
        - Kernel crash logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation often results in kernel crashes.
  mitigation_plan:
    - priority: immediate
      action: Apply kernel patch to lock z_waitq_head usage
      owner: IT Operations
      addresses: CVE-2026-78118
      evidence: Source describes the fix as splitting z_waitq_head and locking the timer expiration handler.
updates:
  - at: "2026-10-21T19:59:24Z"
    level: L2
    summary: added coverage for Zephyr RTOS (with CONFIG_MCTP and CONFIG_MCTP_I2C_GPIO_TARGET enabled)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-79976
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
