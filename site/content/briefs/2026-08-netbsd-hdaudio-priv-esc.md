---
title: NetBSD Local Privilege Escalation via hdaudio Driver
slug: 2026-08-netbsd-hdaudio-priv-esc
description: An unprivileged local attacker can trigger a use-after-free condition in the NetBSD hdaudio(4) driver by exploiting a missing access check on /dev/hdaudioN nodes to invoke the HDAUDIO_FGRP_SETCONFIG ioctl.
date: "2026-08-12T14:46:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - netbsd
  - kernel-vulnerability
vendors:
  - NetBSD
products:
  - NetBSD
affected_os:
  - NetBSD
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: By triggering a race condition between threads during hdafg_detach(), an attacker can cause a use-after-free condition... resulting in outcomes ranging from audio-subsystem denial of service and kernel panic to potential local kernel privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-53996
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53996
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch NetBSD kernel for CVE-2026-53996.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-53996 indicates a kernel-level use-after-free vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict permissions on /dev/hdaudio* nodes to prevent unauthorized access.
      owner: System Administration
      addresses: CVE-2026-53996
      evidence: Vulnerability requires access to /dev/hdaudioN.
---

The NetBSD hdaudio(4) driver (sys/dev/hdaudio/hdaudio.c) contains a critical missing access control vulnerability, tracked as CVE-2026-53996. The vulnerability stems from the absence of required access checks when interacting with /dev/hdaudioN device nodes. This flaw allows an unprivileged local user to invoke the HDAUDIO_FGRP_SETCONFIG ioctl, which should be restricted. By exploiting this lack of access control, an attacker can initiate a race condition between the stream_stop() and stream_disestablish() functions during hdafg_detach(). This race condition leads to a use-after-free scenario where a latched DMA interrupt dereferences a callback pointer that has already been freed. Depending on the memory state, this can result in a denial of service via kernel panic or, in specific conditions, local kernel privilege escalation. Defenders should prioritize patching systems running NetBSD kernels that utilize the hdaudio driver.

## Attack Chain

1. Attacker establishes a low-privileged local session on a NetBSD target.
2. Attacker identifies available audio device nodes at /dev/hdaudio*.
3. Attacker opens a targeted /dev/hdaudioN device node without specific user permissions.
4. Attacker launches a multi-threaded process to interact with the HDAUDIO_FGRP_SETCONFIG ioctl.
5. Thread 1 repeatedly invokes the HDAUDIO_FGRP_SETCONFIG ioctl to trigger detach procedures.
6. Thread 2 maintains active DMA and IRQs, forcing a race condition during the hdafg_detach() call.
7. The kernel dereferences a freed callback pointer due to the race between stream_stop() and stream_disestablish().
8. System crashes (DoS) or attacker achieves kernel-mode code execution (Privilege Escalation).

## Impact

Successful exploitation of CVE-2026-53996 allows any local user on a NetBSD system to cause a system-wide kernel panic, disrupting service availability. Furthermore, the use-after-free vulnerability provides a vector for local privilege escalation, potentially allowing an attacker to gain kernel-level execution rights, bypass filesystem permissions, and gain full control of the affected host.

## Recommendation

* Apply the vendor-provided patch for CVE-2026-53996 to all NetBSD systems.
* Audit local system access to determine if unprivileged users have legitimate business needs to access /dev/hdaudio* device nodes.
* Implement Udev-style rules or manual permission management to restrict read/write access to /dev/hdaudio* to authorized users or groups only.
