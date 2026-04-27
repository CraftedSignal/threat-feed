---
title: Out-of-Cancel Vulnerability Class in Linux Workqueue Cancellation APIs
slug: 2026-03-out-of-cancel
description: The 'Out-of-Cancel' vulnerability class stems from flaws in Linux workqueue cancellation APIs, potentially leading to exploitable conditions within the kernel.
date: "2026-03-25T07:30:12Z"
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

The 'Out-of-Cancel' vulnerability class, discovered and detailed in March 2026, highlights a category of security flaws residing within the workqueue cancellation APIs in the Linux kernel. This vulnerability arises when work items are improperly handled during cancellation, potentially leading to use-after-free conditions, race conditions, and other memory corruption issues. The initial report and analysis were published on March 23, 2026. While specific exploits are not detailed in the source…
