---
title: Intel EPT Paging Code Vulnerability (CVE-2026-23554) Allows Unauthorized Memory Access
slug: 2024-01-intel-ept-paging-vuln
description: The Intel EPT paging code vulnerability (CVE-2026-23554) allows access to unintended memory regions due to improper handling of cached EPT state during paging structure freeing.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - intel
  - ept
  - paging
  - virtualization
  - memory access
  - cve-2026-23554
vendors:
  - Intel
products:
  - Intel Processors
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23554
rules:
  - title: Detect Guest OS Triggering Frequent Page Table Modifications
    description: Detects a guest OS rapidly modifying page tables, which could be an attempt to trigger the EPT vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - hypervisor
      - vmware|xen|kvm
  - title: Detect Access to Unintended Memory Regions by Guest OS
    description: Detects a guest OS accessing memory regions outside of its allocated range, possibly due to stale EPT entries.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - hypervisor
      - vmware|xen|kvm
rules_count: 2
---

The Intel Extended Page Tables (EPT) paging code contains a vulnerability, identified as CVE-2026-23554, related to the handling of cached EPT state. An optimization within the EPT code defers the flushing of cached EPT state until the p2m lock is released. However, the freeing of paging structures is not deferred in the same manner, which leads to a race condition. Specifically, freed pages can be transiently present in the cached state, resulting in stale entries. These stale entries can point to memory ranges that are not owned by the guest virtual machine, potentially allowing unauthorized access to sensitive memory regions and leading to information disclosure or privilege escalation. This vulnerability affects systems utilizing Intel processors with EPT functionality and requires immediate attention from virtualization platform vendors and system administrators.

## Attack Chain

1. A malicious guest OS attempts to trigger memory allocation and deallocation operations.
2. The Intel EPT paging code initiates a modification of the page table, acquiring the p2m lock.
3. The EPT code schedules a flush of the cached EPT state, but defers the actual flush until the p2m lock is released.
4. Before the flush occurs, the memory page associated with the modified page table entry is freed.
5. The freed page is now available for reuse by other processes or virtual machines.
6. The cached EPT state still contains a stale entry pointing to the now-freed memory page.
7. Another process or VM allocates the previously freed memory page.
8. Due to the stale EPT entry, the malicious guest OS can now access the memory contents of the newly allocated page, leading to information disclosure or potentially code execution.

## Impact

Successful exploitation of CVE-2026-23554 could allow a malicious guest operating system to read or write memory belonging to other virtual machines or the hypervisor itself. This could lead to complete compromise of the affected system, including information disclosure, privilege escalation, and denial of service. The vulnerability has a CVSS v3.1 base score of 7.8, indicating a high severity. The potential impact spans across various sectors utilizing virtualization technologies, including cloud service providers, data centers, and enterprise environments.

## Recommendation

*   Apply the patch or mitigation provided by Intel or your virtualization platform vendor to address CVE-2026-23554 as soon as it becomes available.
*   Monitor hypervisor logs for unusual memory access patterns that may indicate exploitation of this vulnerability. Enable appropriate logging within the hypervisor to capture EPT-related events.
