---
title: Creolabs Gravity Heap Buffer Overflow Vulnerability (CVE-2026-40504)
slug: 2026-04-creolabs-gravity-heap-overflow
description: Creolabs Gravity before 0.9.6 is vulnerable to a heap buffer overflow in the gravity_vm_exec function, allowing attackers to achieve arbitrary code execution by crafting scripts with many string literals at global scope that exploit insufficient bounds checking in gravity_fiber_reassign().
date: "2026-04-16T02:16:11Z"
severities:
  - critical
tags:
  - cve
  - heap-overflow
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40504
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40504
  - https://github.com/marcobambini/gravity/commit/18b9195598d9b944376754c6d1ad76e38a4adca1
  - https://github.com/marcobambini/gravity/issues/437
  - https://github.com/marcobambini/gravity/releases/tag/0.9.6
  - https://www.vulncheck.com/advisories/creolabs-gravity-heap-buffer-overflow-via-gravity-vm-exec
rules:
  - title: Detect Suspicious Process Creation After Potential Creolabs Gravity Exploitation
    description: Detects suspicious process creation events that may indicate successful exploitation of the Creolabs Gravity heap overflow vulnerability (CVE-2026-40504).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Memory Corruption by String Overwrite
    description: Detects potential heap corruption by string operations.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Creolabs Gravity, a scripting language, is susceptible to a heap buffer overflow vulnerability (CVE-2026-40504) affecting versions prior to 0.9.6. The vulnerability resides within the `gravity_vm_exec` function and can be triggered by crafting Gravity scripts containing a large number of string literals declared at the global scope. This leads to an out-of-bounds write, potentially corrupting heap metadata. Successful exploitation of this vulnerability can lead to arbitrary code execution…
