---
title: 'GPUBreach: GPU Rowhammer Attack for Privilege Escalation'
slug: 2026-04-gpubreach-rowhammer
description: GPUBreach is a novel Rowhammer attack targeting GPUs, allowing privilege escalation to root shell by inducing bit flips in GDDR6 memory and exploiting memory-safety bugs in Nvidia drivers, posing a significant risk to shared cloud environments.
date: "2026-04-07T11:31:38Z"
severities:
  - critical
tags:
  - rowhammer
  - privilege-escalation
  - gpu
  - cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.securityweek.com/gpubreach-root-shell-access-achieved-via-gpu-rowhammer-attack/
rules:
  - title: GPU Memory Hammering Detection
    description: Detects potential GPU memory hammering activity based on excessive memory access patterns
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Suspicious GPU Privilege Escalation
    description: Detects processes utilizing GPUs followed by privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A team of researchers from the University of Toronto has discovered a new Rowhammer attack named GPUBreach, which exploits GDDR6 memory in Nvidia GPUs. This attack induces bit flips that corrupt GPU page tables. In combination with existing memory-safety bugs in Nvidia drivers, GPUBreach enables arbitrary read-write access to memory. This ultimately leads to CPU-side privilege escalation, resulting in a root shell and full system compromise. This poses a significant threat to cloud…
