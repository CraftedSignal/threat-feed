---
brief_id: brief-2026-11-03-zephyr-can-uaf
event_id: brief-2026-11-03-zephyr-can-uaf
revision: 1
activity_at: "2026-11-03T16:01:06Z"
title: 'Zephyr RTOS: Use-after-free in CAN subsystem (CVE-2026-85035)'
slug: 2026-11-zephyr-can-uaf
description: A use-after-free vulnerability in the Zephyr RTOS CAN subsystem allows unprivileged user-mode threads to trigger kernel heap corruption via dangling pointers in the can_add_rx_filter_msgq() system call.
date: "2026-11-03T16:01:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "6"
  rating: A6
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-85035 description
cpes:
  - cpe:2.3:o:zephyrproject:zephyr:*:*:*:*:*:*:*:*
tags:
  - kernel-vulnerability
  - use-after-free
  - zephyr
vendors:
  - Zephyr Project
products:
  - Zephyr RTOS (< patched version)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This yields kernel-heap corruption reachable from a user-mode thread, defeating the isolation CONFIG_USERSPACE is intended to provide.
    confidence_band: high
cves:
  - id: CVE-2026-85035
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85035
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Identify use of dynamic message queues with CAN subsystems in user-mode accessible firmware
      technique_id: T1068
      data_needed:
        - Source code analysis or firmware binary analysis for K_OBJ_MSGQ usage in can_add_rx_filter_msgq
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The dangling pointer arises when a thread exits without calling can_remove_rx_filter() or releases a dynamic object
  mitigation_plan:
    - priority: immediate
      action: Patch Zephyr RTOS firmware to use static message queue validation
      owner: IT Operations
      addresses: CVE-2026-85035
      evidence: The fix validates the queue with K_SYSCALL_OBJ_STATIC()
---

CVE-2026-85035 is a use-after-free vulnerability in the Zephyr RTOS CAN subsystem. The system call `can_add_rx_filter_msgq()` fails to validate the lifetime of `struct k_msgq` objects passed as `user_data` for filter callbacks. When `CONFIG_USERSPACE` and `CONFIG_DYNAMIC_OBJECTS` are enabled, an unprivileged thread can register a dynamically allocated message queue, release the object while the kernel retains a pointer to it, and trigger heap corruption when a CAN frame is processed. This enables potential privilege escalation by overwriting kernel structures.

## Attack Chain

1. Attacker ensures `CONFIG_USERSPACE` and `CONFIG_DYNAMIC_OBJECTS` are active in the target Zephyr image.
2. Attacker obtains permission to interface with a CAN device.
3. Attacker allocates a message queue using `k_object_alloc(K_OBJ_MSGQ)` and `k_msgq_alloc_init()`.
4. Attacker registers the queue via `can_add_rx_filter_msgq()`, which places a raw pointer to the queue in the kernel filter table.
5. Attacker calls `k_object_release()` or terminates, causing the kernel to free the queue memory while the filter remains active.
6. Attacker grooms the kernel heap to place controlled data in the memory previously occupied by the queue.
7. A CAN frame matching the filter is received, triggering `can_msgq_put()` in supervisor context against the now-controlled memory, leading to heap corruption.

## Recommendation

* Apply the official Zephyr Project patch that enforces `K_SYSCALL_OBJ_STATIC()` validation for `can_add_rx_filter_msgq()`.
* For firmware developers, ensure that dynamically allocated message queues are not used in conjunction with CAN RX filters in user-mode contexts.
