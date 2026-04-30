---
title: Out-of-Cancel Vulnerability Class in Linux Workqueue Cancellation APIs
slug: 2026-03-out-of-cancel
description: The 'Out-of-Cancel' vulnerability class stems from flaws in Linux workqueue cancellation APIs, potentially leading to exploitable conditions within the kernel.
date: "2026-03-25T07:30:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - linux
  - kernel
  - vulnerability
  - workqueue
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s343im/outofcancel_a_vulnerability_class_rooted_in/
  - https://v4bel.github.io/linux/2026/03/23/ooc.html
rules:
  - title: Detect Potential Use-After-Free in Workqueue Cancellation
    description: Detects potential use-after-free conditions related to workqueue cancellations by monitoring for specific kernel events.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Kernel Module Loading with Workqueue
    description: Detects loading of kernel modules that might be related to workqueue exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.004
    data_sources:
      - image_load
      - linux
rules_count: 2
---

The 'Out-of-Cancel' vulnerability class, discovered and detailed in March 2026, highlights a category of security flaws residing within the workqueue cancellation APIs in the Linux kernel. This vulnerability arises when work items are improperly handled during cancellation, potentially leading to use-after-free conditions, race conditions, and other memory corruption issues. The initial report and analysis were published on March 23, 2026. While specific exploits are not detailed in the source material, the nature of kernel vulnerabilities makes them critical for defenders to address. The impact can range from denial of service to privilege escalation and potentially arbitrary code execution within the kernel context. This vulnerability class affects a broad range of Linux systems, making it a widespread concern.

## Attack Chain

1. A user-space program triggers a specific kernel function that queues a work item to a workqueue.
2. The work item is scheduled for execution, but before it begins, the user-space program requests cancellation of the work item via a workqueue cancellation API.
3. Due to a race condition or improper synchronization, the work item is canceled but not fully removed from the workqueue's internal data structures.
4. The kernel attempts to access the work item after it has been freed, resulting in a use-after-free vulnerability.
5. An attacker manipulates memory layout to place controlled data at the memory location of the freed work item.
6. The kernel code now operates on the attacker-controlled data, leading to memory corruption or information leakage.
7. The attacker leverages the memory corruption to overwrite critical kernel data structures, such as function pointers or security credentials.
8. Successful exploitation leads to privilege escalation, allowing the attacker to execute arbitrary code with kernel-level privileges.

## Impact

The 'Out-of-Cancel' vulnerability class can lead to severe consequences, including kernel crashes (denial of service), privilege escalation, and potentially arbitrary code execution within the kernel. A successful exploit could allow an attacker to gain complete control over the affected system. Due to the ubiquitous nature of the Linux kernel, a wide range of systems are potentially vulnerable, impacting servers, desktops, embedded systems, and mobile devices. While the exact number of vulnerable systems is unknown, the widespread use of affected kernel versions implies a significant potential impact.

## Recommendation

*   Monitor kernel logs for errors related to workqueue cancellations to detect potential exploitation attempts. Enable auditd to log kernel function calls related to workqueue management (audit.rules).
*   Deploy the Sigma rule `Detect Potential Use-After-Free in Workqueue Cancellation` to identify suspicious kernel events related to workqueue operations.
*   Investigate any reported kernel panics or crashes, focusing on stack traces that involve workqueue-related functions.
*   Stay informed about kernel patches and security advisories related to workqueue vulnerabilities and apply them promptly.
