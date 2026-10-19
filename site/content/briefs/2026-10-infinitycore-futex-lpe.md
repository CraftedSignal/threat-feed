---
title: InfinityCore Android Futex Race Condition Privilege Escalation
slug: 2026-10-infinitycore-futex-lpe
description: A local privilege escalation vulnerability (CVE-2026-80775) in the InfinityCore Android kernel allows attackers to achieve root access via a race condition in the Futex subsystem.
date: "2026-10-19T00:59:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:infinitycore:android:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - kernel
  - android
  - cve-2026-80775
vendors:
  - InfinityCore
products:
  - InfinityCore Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The escalation is triggered by using a pipe ring to reclaim the released hash, with the privilege escalation point located at task_struct->cred.
    confidence_band: high
cves:
  - id: CVE-2026-80775
    epss: 0.00168
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Review kernel patch level and contact InfinityCore support for CVE-2026-80775 remediation.
      owner: IT Operations
      due: 48h
      evidence: Public exploit exists for CVE-2026-80775.
  hunt_leads:
    - lead: Identify applications invoking prctl with PR_FUTEX_HASH syscalls in unexpected contexts.
      technique_id: T1068
      data_needed:
        - Android kernel audit logs or syscall monitoring
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploit requires precise syscall manipulation of PR_FUTEX_HASH.
  mitigation_plan:
    - priority: immediate
      action: Patch kernel to address Futex subsystem race condition.
      owner: IT Operations
      addresses: CVE-2026-80775
      evidence: The availability of a working exploit significantly elevates the risk for unpatched systems.
---

CVE-2026-80775 is a critical memory corruption vulnerability identified in the InfinityCore Android kernel's Futex subsystem. The flaw arises from a race condition triggered when two tasks share an mm_struct through nested vfork() calls during the allocation of a FUTEX_PRIVATE_HASH reference counter. If the tasks publish conflicting per-CPU counter addresses to the shared memory, a reference is lost, leading to an incorrect hash release and subsequent use-after-free access when the kernel later attempts to use the freed bucket pointer. An attacker can leverage this use-after-free condition to corrupt kernel memory and overwrite the task_struct->cred structure, effectively elevating the process's privilege to root (UID 0). A proof-of-concept exploit targeting the ARM64 platform has been publicly released, necessitating urgent attention for kernel updates.

## Attack Chain

1. The exploit performs initial environment probing by calling prctl(PR_FUTEX_HASH, GET_SLOTS) to confirm kernel compatibility.
2. The process enters an iterative loop (up to 256 times) to manipulate the Futex hash layout, setting hash slots to 8.
3. A helper process is spawned and synchronized using clock_nanosleep(TIMER_ABSTIME) to facilitate precise preemption timing.
4. A target process is created, which acquires a warm lock before dropping its scheduling priority to SCHED_IDLE (nice 19) to create the race window.
5. The primary controller resizes the Futex hash to 2^18, triggering the race condition while the helper process is sleeping.
6. The exploit floods the system with pipe structures to reclaim the memory previously freed by the Futex hash release.
7. The attacker-controlled memory inside the pipe buffer is used to overwrite the task_struct->cred object in the kernel.
8. Upon successful overwrite, the process UID is elevated to zero, resulting in the execution of a root-privileged /system/bin/sh shell.

## Impact

The vulnerability allows any local unprivileged application or user on an affected Android device to achieve full root privileges. Successful exploitation results in complete compromise of the device's security model, bypassing all permission boundaries and allowing for arbitrary code execution with kernel-level authority, data exfiltration, and persistent access.

## Recommendation

1. Monitor for kernel updates from InfinityCore and apply the patch addressing CVE-2026-80775 immediately.
2. Implement kernel-level integrity monitoring to detect anomalous modifications to task_struct credentials.
3. Restrict the ability of untrusted applications to utilize advanced Futex operations or custom system call flags if the kernel interface can be hardened.
4. Perform memory forensic analysis on devices suspected of unauthorized privilege escalation to identify potential use-after-free corruption artifacts.
