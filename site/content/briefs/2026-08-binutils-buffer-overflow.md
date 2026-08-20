---
title: Stack-Based Buffer Overflow in Binutils (CVE-2026-19582)
slug: 2026-08-binutils-buffer-overflow
description: A stack-based buffer overflow vulnerability in binutils versions 2.46.1 and prior allows attackers to achieve arbitrary code execution by enticing a victim to process a maliciously crafted Portable Executable (PE) file.
date: "2026-08-20T07:11:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - binutils
  - memory-corruption
vendors:
  - Red Hat
products:
  - binutils
  - Red Hat Enterprise Linux 6
  - Red Hat Enterprise Linux 7
  - Red Hat Enterprise Linux 10
affected_os:
  - RHEL 6
  - RHEL 7
  - RHEL 10
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A victim who opens a crafted PE file using binutils could execute arbitrary code unknowningly via a stack buffer overflow out of bounds write.
    confidence_band: high
cves:
  - id: CVE-2026-19582
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19582
  - https://access.redhat.com/security/cve/CVE-2026-19582
  - https://bugzilla.redhat.com/show_bug.cgi?id=2513754
---

Binutils versions 2.46.1 and prior contain a critical vulnerability (CVE-2026-19582) stemming from a stack-based buffer overflow during the processing of Portable Executable (PE) files. The flaw, categorized as an out-of-bounds write (CWE-787), occurs when the utility incorrectly handles specially crafted input files. By convincing a user to open or process a malicious PE file using the affected binutils packages, an attacker can trigger memory corruption, potentially leading to arbitrary code execution with the privileges of the user running the utility. This vulnerability is particularly concerning for environments where binutils or associated tools like GDB are used to analyze untrusted binary files. The issue has been confirmed by Red Hat, impacting several iterations of their enterprise distributions.

## Attack Chain

1. An attacker constructs a malicious PE file containing malformed headers or data structures specifically designed to trigger a stack overflow in binutils.
2. The attacker delivers the file to the target user via phishing, social engineering, or shared file repositories.
3. The victim triggers the execution of a binutils utility (e.g., objdump, readelf, or strings) against the malicious PE file.
4. The binutils component parses the file's malformed structure.
5. The vulnerability in the parsing logic causes an out-of-bounds write to the stack, overwriting adjacent memory.
6. The corrupted stack memory is used to redirect program control flow.
7. The attacker's shellcode or return-oriented programming (ROP) chain is executed within the context of the user running the utility.
8. Final objective achieved: local code execution on the target system.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the victim, which may lead to full system compromise if the victim is a privileged user. This vulnerability impacts multiple versions of Red Hat Enterprise Linux (RHEL 6, 7, and 10) that ship with the affected binutils packages. Given that these tools are commonly used by developers and security analysts to inspect binary files, the risk surface includes local workstation environments and automated build or analysis pipelines.

## Recommendation

* Apply the security patches provided by Red Hat for the binutils and associated toolchain packages immediately.
* Audit build and analysis pipelines to ensure that automated tools do not process files from untrusted sources without sandboxing.
* Monitor file system logs for unexpected execution of binutils utilities (e.g., objdump, readelf) on untrusted files or within temp directories.
* Implement memory integrity controls on build servers and workstations to mitigate the impact of buffer overflow exploitation.
