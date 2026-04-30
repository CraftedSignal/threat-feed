---
title: 'GPUBreach: GPU Rowhammer Attack for Privilege Escalation'
slug: 2026-04-gpubreach-rowhammer
description: GPUBreach is a novel Rowhammer attack targeting GPUs, allowing privilege escalation to root shell by inducing bit flips in GDDR6 memory and exploiting memory-safety bugs in Nvidia drivers, posing a significant risk to shared cloud environments.
date: "2026-04-07T11:31:38Z"
type: advisory
types:
  - advisory
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

A team of researchers from the University of Toronto has discovered a new Rowhammer attack named GPUBreach, which exploits GDDR6 memory in Nvidia GPUs. This attack induces bit flips that corrupt GPU page tables. In combination with existing memory-safety bugs in Nvidia drivers, GPUBreach enables arbitrary read-write access to memory. This ultimately leads to CPU-side privilege escalation, resulting in a root shell and full system compromise. This poses a significant threat to cloud environments, where multiple users share the same physical GPU. The researchers reported their findings to Nvidia in November 2025. Google awarded a $600 bounty for the vulnerability discovery.

## Attack Chain

1.  Attacker gains code execution privileges on a GPU within a shared environment (e.g., cloud).
2.  Attacker utilizes the GPUBreach technique to repeatedly access ("hammer") a specific row of GDDR6 memory cells on the GPU.
3.  This "hammering" generates electrical interference, causing bit flips in neighboring memory regions.
4.  The induced bit flips corrupt GPU page tables, granting arbitrary read-write access to memory.
5.  Attacker exploits memory-safety bugs in Nvidia drivers.
6.  This leads to CPU-side privilege escalation by exploiting the corrupted memory access.
7.  Attacker gains root shell privileges on the compromised system.
8.  Attacker achieves full system compromise, potentially leading to unauthorized data access, data corruption, or breaches of memory isolation.

## Impact

The GPUBreach attack allows for privilege escalation from a user with GPU access to root on a shared system. This compromises the confidentiality, integrity, and availability of the entire system, especially in cloud environments where multiple users share physical GPUs. Successful exploitation can lead to unauthorized data access, data corruption, breaches of memory isolation, and potentially complete control over the compromised system. Google awarded a $600 bounty highlighting the significance of this vulnerability.

## Recommendation

*   Enable ECC on server and workstation GPUs (e.g., RTX A6000) as per the Nvidia security notice to mitigate single-bit flips, although this is not a foolproof mitigation as the attack can induce more than two bit flips.
*   Monitor GPU resource usage for unusual memory access patterns indicative of Rowhammer attacks using the detection rule for `GPU Memory Hammering Detection`.
*   Monitor for suspicious processes utilizing the GPU in conjunction with privilege escalation attempts as detected by the `Suspicious GPU Privilege Escalation` Sigma rule.
