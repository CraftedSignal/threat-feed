---
title: NovumOS Local Privilege Escalation via Unvalidated Syscall
slug: 2026-04-novumos-lpe
description: A local privilege escalation vulnerability exists in NovumOS versions before 0.24, where Syscall 12 (JumpToUser) lacks input validation, allowing user-mode processes to execute arbitrary code in kernel mode.
date: "2026-04-18T01:16:19Z"
severities:
  - critical
tags:
  - privilege-escalation
  - syscall
  - novumos
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40317
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40317
rules:
  - title: Detect Syscall 12 Invocation from User Space
    description: Detects invocations of Syscall 12, JumpToUser, which might indicate an attempt to exploit CVE-2026-40317 in vulnerable versions of NovumOS.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - syscall
      - linux
  - title: Detect Kernel Memory Modification from User Space
    description: Detects attempts by user-space processes to directly modify kernel memory regions, which could be indicative of CVE-2026-40317 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - memory_event
      - linux
  - title: Monitor indirect calls
    description: Monitor for changes in the memory map that may indicate a JumpToUser call. This rule looks for an executable page with memory protection PROT_EXEC
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - memory_event
      - linux
rules_count: 3
---

NovumOS, a custom 32-bit operating system built with Zig and x86 Assembly, is vulnerable to a critical privilege escalation. Prior to version 0.24, Syscall 12, known as JumpToUser, fails to validate the entry point address provided by user-space registers. This flaw allows any process running in Ring 3 (user mode) to redirect execution to kernel addresses, thereby executing arbitrary code within the Ring 0 context (kernel mode). This effectively grants user-level processes complete control over…
