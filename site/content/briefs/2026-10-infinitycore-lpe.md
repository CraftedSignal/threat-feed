---
title: Local Privilege Escalation in InfinityCore Android Scheduler
slug: 2026-10-infinitycore-lpe
description: CVE-2026-98385 is a local privilege escalation vulnerability in the InfinityCore Android scheduler stemming from a use-after-free condition in per-CPU cache statistics, allowing attackers to overwrite task credentials.
date: "2026-10-19T00:59:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:infinitycore:android_scheduler:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - android
  - kernel-exploit
vendors:
  - InfinityCore
products:
  - InfinityCore Android Scheduler
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Exploit reclaims the freed hash using a pipe ring, and escalates privilege escalation to task_struct->cred.
    confidence_band: high
cves:
  - id: CVE-2026-98385
    epss: 0.00145
references:
  - https://sploitus.com/exploit?id=BCD81CD3-5587-5787-B2F1-B77A1BA2CB80
action_plan:
  priority: elevated
  owners:
    - SOC
    - System Administration
  immediate_actions:
    - action: Check kernel configuration for CONFIG_SCHED_CACHE and sysctl_sched_cache_user
      owner: System Administration
      due: 48h
      evidence: Source states exploit requires CONFIG_SCHED_CACHE=y and sysctl_sched_cache_user != 0
  mitigation_plan:
    - priority: immediate
      action: Disable CONFIG_SCHED_CACHE via kernel recompilation or sysctl_sched_cache_user if possible
      owner: System Administration
      addresses: CVE-2026-98385
      evidence: Source prerequisite requirements
---

CVE-2026-98385 is a local privilege escalation (LPE) vulnerability affecting the InfinityCore Android scheduler. The flaw originates in the scheduler's cache accounting mechanism, which fails to protect the lifecycle of per-CPU statistics associated with a task's mm_struct. When a task performs an exec() call on a different CPU, the address space can be replaced, leading to a race condition where the scheduler continues to write to the old address space. 

This results in memory corruption that an attacker can leverage to target the reference counter of a private futex hash. By reclaiming the freed hash memory using a pipe ring, an attacker can manipulate kernel structures to overwrite the task_struct->cred, effectively granting the attacker root privileges. Successful exploitation requires specific kernel configurations: CONFIG_SCHED_CACHE must be enabled, sched_cache_active must be active at runtime, the system must support SD_SHARE_LLC with multiple CPUs, and sysctl_sched_cache_user must not be set to zero.

## Attack Chain

1. Attacker initializes a malicious environment by confirming CONFIG_SCHED_CACHE=y and sysctl_sched_cache_user != 0.
2. The exploit process uses sched_setattr to establish scheduling parameters for capability verification.
3. The process allocates a 128 MB address space buffer to facilitate page churn.
4. A victim process is forked and set to SCHED_IDLE, periodically invoking execve to free its own mm_struct.
5. A helper thread creates page fluctuations using readv(/dev/zero) and nanosleep to induce the race condition.
6. The main thread performs an iterative loop (up to 4096 times) of sched_setattr to trigger the use-after-free in the futex hash.
7. The exploit reclaims the freed futex hash memory using a pipe ring to facilitate arbitrary data manipulation.
8. The exploit overwrites the task_struct->cred of the current process to set the UID to zero, followed by spawning /system/bin/sh.

## Impact

Successful exploitation of CVE-2026-98385 results in a complete compromise of the affected Android device. An unprivileged attacker can transition to root privileges, bypassing system security controls and gaining full read/write access to the device filesystem, user data, and system binaries. This vulnerability impacts any Android implementation utilizing the vulnerable InfinityCore scheduler code path with the specified kernel configurations enabled.

## Recommendation

1. Audit kernel configurations on Android deployments to verify if CONFIG_SCHED_CACHE is enabled; if unnecessary, disable the feature in the kernel build.
2. Monitor and restrict the sysctl_sched_cache_user setting; ensure it is set to zero if the scheduler cache feature is not required for production workloads.
3. Implement kernel-level integrity monitoring to detect anomalous writes to the task_struct structure.
4. Deploy updates provided by the device manufacturer or InfinityCore maintainers that apply the patch for CVE-2026-98385.
5. Perform local security assessments using kernel BTF or vmlinux symbols to identify if the target kernel is susceptible to the defined structure offsets in the LPE chain.
