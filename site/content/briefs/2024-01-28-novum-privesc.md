---
title: NovumOS MemoryMapRange Privilege Escalation Vulnerability (CVE-2026-40572)
slug: 2024-01-28-novum-privesc
description: A vulnerability exists in NovumOS versions prior to 0.24 where the MemoryMapRange syscall allows user-mode processes to map arbitrary virtual address ranges, including kernel structures, leading to privilege escalation.
date: "2026-04-18T01:16:19Z"
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

NovumOS, a custom 32-bit operating system written in Zig and x86 Assembly, is vulnerable to a critical privilege escalation flaw. Specifically, versions prior to 0.24 contain a vulnerability in Syscall 15, also known as MemoryMapRange. This syscall allows Ring 3 user-mode processes to map arbitrary virtual address ranges into their address space. This includes forbidden regions that should be protected, such as critical kernel structures including the Interrupt Descriptor Table (IDT), Global…
