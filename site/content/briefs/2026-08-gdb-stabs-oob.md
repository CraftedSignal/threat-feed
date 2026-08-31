---
title: Remote Code Execution in GNU Debugger (GDB) via Malicious STABS Debug Data
slug: 2026-08-gdb-stabs-oob
description: A memory corruption vulnerability in GDB's STABS parser allows an attacker to achieve arbitrary code execution by providing a crafted ELF binary containing malicious debug sections.
date: "2026-08-31T21:59:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gnu:gdb:*:*:*:*:*:*:*:*
vendors:
  - GNU
products:
  - GDB
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can craft an ELF binary with malicious .stab and .stabstr sections that triggers this out-of-bounds write when a user opens the file in GDB and performs any symbol-inspection operation.
    confidence_band: high
cves:
  - id: CVE-2026-13732
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13732
action_plan:
  priority: elevated
  owners:
    - Security Operations
    - Development Teams
  immediate_actions:
    - action: Upgrade GDB to the vendor-patched version once released.
      owner: IT Operations
      due: 7d
      evidence: Source mentions vulnerability in gdb/stabsread.c.
  mitigation_plan:
    - priority: immediate
      action: Use sandboxed environments for analyzing untrusted ELF binaries.
      owner: Security Operations
      addresses: CVE-2026-13732
      evidence: Exploit triggers when opening binary in GDB.
---

A memory corruption vulnerability (CVE-2026-13732) exists in the GNU Debugger (GDB) within the STABS debug format parser. The flaw originates in the `read_member_functions()` function located in `gdb/stabsread.c`, where a linked list removal error occurs during the separation of destructor and non-destructor member functions of C++ classes. This error causes destructor entries to persist in the function list while the list length counter is decremented, leading to an out-of-bounds write when the list is copied to its final array. An attacker can weaponize this by crafting an ELF binary with malicious `.stab` and `.stabstr` sections. Triggering the vulnerability requires only that a user open the malicious file in GDB and perform basic symbol inspection, such as setting a breakpoint; execution of the binary itself is not required. This allows for arbitrary command execution within the context of the GDB process, presenting a significant risk to developers and security researchers who handle untrusted binaries.

## Attack Chain

1. Attacker generates a malicious ELF binary with specially crafted `.stab` and `.stabstr` sections.
2. The malicious ELF binary is distributed to a target developer or security researcher.
3. The victim opens the malicious ELF binary using GDB.
4. The victim performs a standard symbol-inspection operation, such as listing symbols or setting a breakpoint.
5. GDB invokes the `read_member_functions()` function to parse the malformed STABS debug data.
6. The logic error causes an out-of-bounds write during the management of the C++ member function linked list.
7. The out-of-bounds write corrupts heap memory to overwrite function pointers or control structures.
8. GDB executes arbitrary attacker-supplied shellcode within the security context of the user running the debugger.

## Impact

Successful exploitation leads to arbitrary command execution within the context of the GDB process. This could allow an attacker to compromise the development environment, exfiltrate sensitive source code, or install persistent backdoors on the analyst's machine. The threat is particularly relevant to developers, reverse engineers, and malware analysts who frequently interact with untrusted binaries.

## Recommendation

1. Update GDB to the latest version that includes the patch for CVE-2026-13732 as soon as it is made available by the GNU project.
2. Exercise caution when opening binary files with GDB if the source or integrity of the binary cannot be verified.
3. Run GDB within a sandboxed environment, such as a container or virtual machine, when analyzing unknown or untrusted ELF files to limit the potential impact of a successful exploit.
