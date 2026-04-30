---
title: NovumOS MemoryMapRange Privilege Escalation Vulnerability (CVE-2026-40572)
slug: 2024-01-28-novum-privesc
description: A vulnerability exists in NovumOS versions prior to 0.24 where the MemoryMapRange syscall allows user-mode processes to map arbitrary virtual address ranges, including kernel structures, leading to privilege escalation.
date: "2026-04-18T01:16:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - novumOS
  - CVE-2026-40572
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40572
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40572
rules:
  - title: MemoryMapRange Syscall Invocation
    description: Detects invocations of Syscall 15 (MemoryMapRange) which may indicate attempts to exploit CVE-2026-40572.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-40572
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - syscall
      - novumOS
  - title: Kernel Structure Modification
    description: Detects attempts to modify critical kernel structures, potentially indicating exploitation of CVE-2026-40572.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-40572
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - memory_event
      - novumOS
rules_count: 2
---

NovumOS, a custom 32-bit operating system written in Zig and x86 Assembly, is vulnerable to a critical privilege escalation flaw. Specifically, versions prior to 0.24 contain a vulnerability in Syscall 15, also known as MemoryMapRange. This syscall allows Ring 3 user-mode processes to map arbitrary virtual address ranges into their address space. This includes forbidden regions that should be protected, such as critical kernel structures including the Interrupt Descriptor Table (IDT), Global Descriptor Table (GDT), Task State Segment (TSS), and page tables. An attacker with local access to a vulnerable NovumOS system can exploit this vulnerability to gain kernel-level privileges, allowing for complete system compromise. This vulnerability is identified as CVE-2026-40572, and has a CVSS v3.1 base score of 9.0. The vulnerability is fixed in NovumOS version 0.24.

## Attack Chain

1. A local attacker gains initial access to a NovumOS system. This may involve having an existing user account or exploiting another vulnerability for initial entry.
2. The attacker executes a user-mode process with the intention of escalating privileges.
3. The process invokes Syscall 15 (MemoryMapRange) with arguments specifying a virtual address range corresponding to a critical kernel structure, such as the IDT.
4. Due to the vulnerability in NovumOS versions prior to 0.24, the MemoryMapRange syscall does not properly validate the requested memory region.
5. The syscall allows the user-mode process to successfully map the kernel memory region into its own address space.
6. The attacker modifies the mapped kernel memory, specifically overwriting entries in the IDT to redirect interrupt handlers to attacker-controlled code.
7. An interrupt is triggered, either by a hardware event or a software instruction, causing the system to execute the attacker's code in kernel mode.
8. The attacker now has kernel-level privileges and can perform any action on the system, including installing backdoors, exfiltrating data, or causing a denial of service.

## Impact

Successful exploitation of CVE-2026-40572 allows a local attacker to escalate privileges from user mode to kernel mode on NovumOS systems running versions prior to 0.24. This grants the attacker complete control over the affected system. The attacker can then install persistent backdoors, steal sensitive data, or disrupt system operations. Given the base score of 9.0, this is considered a critical vulnerability.

## Recommendation

*   Upgrade NovumOS installations to version 0.24 or later to patch CVE-2026-40572.
*   Implement system call monitoring to detect suspicious invocations of Syscall 15 (MemoryMapRange). The `MemoryMapRange Syscall Invocation` Sigma rule below can assist with this.
*   Monitor for unexpected modifications to kernel structures such as the IDT, GDT, and TSS. The `Kernel Structure Modification` Sigma rule below can assist with this.
