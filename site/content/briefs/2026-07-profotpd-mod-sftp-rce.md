---
title: ProFTPD mod_sftp Heap Buffer Overflow Leads to Arbitrary Code Execution
slug: 2026-07-profotpd-mod-sftp-rce
description: A heap-based buffer overflow vulnerability exists in the mod_sftp module of ProFTPD versions prior to 1.3.9c and 1.3.10rc3, allowing authenticated low-privilege attackers to achieve arbitrary code execution by sending specially crafted SFTP packet fragments exceeding 16 KB, corrupting memory and redirecting function calls.
date: "2026-07-20T15:19:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - heap-overflow
  - rce
  - sftp
vendors:
  - ProFTPD
products:
  - ProFTPD before 1.3.9c
  - ProFTPD before 1.3.10rc3
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary code execution by sending crafted SFTP packet fragments ... and redirect pr_fsio_stat() to system() via a crafted RENAME request.
    confidence_band: high
cves:
  - id: CVE-2026-63090
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63090
---

ProFTPD, an open-source FTP server, is affected by a critical heap-based buffer overflow vulnerability, CVE-2026-63090, residing within its `mod_sftp` module. This flaw impacts versions prior to 1.3.9c and 1.3.10rc3. Authenticated low-privilege attackers can exploit this vulnerability by dispatching specially crafted SFTP packet fragments that exceed the 16 KB reassembly buffer in the `fxp.c` component. Successful exploitation leads to memory corruption, allowing the attacker to manipulate critical pointers, specifically overwriting the `root_fs` BSS global pointer. This manipulation redirects the `pr_fsio_stat()` function to the `system()` function, enabling arbitrary code execution through a crafted RENAME request. The vulnerability poses a significant risk to the integrity and confidentiality of systems running vulnerable ProFTPD installations.

## Attack Chain

1. An authenticated low-privilege attacker establishes an SFTP connection to a vulnerable ProFTPD server.
2. The attacker crafts and sends SFTP packet fragments that intentionally exceed the 16 KB reassembly buffer size in the `mod_sftp` module's `fxp.c` component.
3. The oversized fragments trigger an incorrectly conditioned reallocation within the server's memory management.
4. This leads to a heap-based buffer overflow, corrupting pool freelist metadata in memory.
5. The attacker then manipulates the corrupted memory to overwrite the `root_fs` BSS global pointer, redirecting it to reference a fake filesystem structure.
6. This pointer redirection causes subsequent calls to the `pr_fsio_stat()` function to instead execute the `system()` function.
7. The attacker sends a crafted RENAME request, which now serves as a vehicle to pass arbitrary commands to the `system()` function.
8. Arbitrary code execution is achieved on the underlying server with the privileges of the ProFTPD process.

## Impact

Successful exploitation of CVE-2026-63090 grants an authenticated low-privilege attacker arbitrary code execution capabilities on the affected server. This allows the attacker to execute any commands with the privileges of the ProFTPD process, potentially leading to full system compromise, data exfiltration, service disruption, or further lateral movement within the network. While no specific victim counts or targeted sectors are mentioned, any organization utilizing vulnerable ProFTPD installations is at risk of severe security breaches, impacting data confidentiality, integrity, and availability.

## Recommendation

* Patch CVE-2026-63090 on all ProFTPD installations by upgrading to versions 1.3.9c, 1.3.10rc3, or later immediately.
* Enable comprehensive logging for ProFTPD servers, specifically focusing on SFTP command logs and system call attempts, to identify unusual activity that could indicate exploitation of CVE-2026-63090.
