---
title: Linux Kernel DirtyDecrypt Local Privilege Escalation (CVE-2026-31635)
slug: 2026-05-dirtydecrypt-lpe
description: CVE-2026-31635, dubbed DirtyDecrypt, is a local privilege escalation vulnerability in the Linux kernel's rxrpc subsystem (rxgk component), allowing an unprivileged user to corrupt page cache and achieve arbitrary file writes, leading to root access on kernels 6.10 to 6.13 with CONFIG_RXGK enabled.
date: "2026-05-19T22:01:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:6.16:-:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc1:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc2:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc3:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc4:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc5:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc6:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.0:rc7:*:*:*:*:*:*
tags:
  - privilege-escalation
  - lpe
  - linux
products:
  - Linux Linux_Kernel
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-31635
    cvss: 7.5
    epss: 0.00055
references:
  - https://sploitus.com/exploit?id=52E2B1D3-F89F-58A5-A1F3-B7D71B13F551&utm_source=rss&utm_medium=rss
  - https://github.com/0xBlackash/DirtyDecrypt
rules:
  - title: Detect DirtyDecrypt Exploit Execution
    description: Detects CVE-2026-31635 exploitation — execution of a binary without a parent process, potentially indicating the DirtyDecrypt exploit
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect RXGK Key Addition
    description: Detects CVE-2026-31635 exploitation — usage of the `keyctl` utility to add RXGK keys, a prerequisite for the DirtyDecrypt exploit
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A local privilege escalation vulnerability, CVE-2026-31635, dubbed "DirtyDecrypt," affects Linux kernels from version 6.10 to 6.13 when `CONFIG_RXGK` is enabled. This vulnerability resides in the `rxrpc` subsystem's `rxgk` component. An unprivileged user can exploit the vulnerability to corrupt the page cache, leading to arbitrary file writes and, ultimately, root access. The public availability of a working exploit significantly increases the risk to vulnerable systems, potentially enabling attackers to gain elevated privileges and compromise affected Linux systems.

## Attack Chain

1.  An unprivileged local user gains access to the target Linux system.
2.  The attacker enters a user and network namespace.
3.  The attacker adds an RXGK key to the keyring using the `keyctl` utility.
4.  The attacker uses `AF_RXRPC` sockets and `splice()` to force page cache pages into the RXGK decryption path.
5.  This triggers in-place AES-CBC decryption without `skb_cow_data()`.
6.  The in-place decryption corrupts the target file (`/etc/passwd`) byte-by-byte using a sliding window technique.
7.  The attacker blanks the root password in `/etc/passwd`.
8.  The attacker spawns a root shell, gaining complete control of the system.

## Impact

Successful exploitation of CVE-2026-31635 allows an unprivileged local user to gain root privileges on the affected system. This can lead to complete system compromise, data theft, and malicious activities. The vulnerability affects systems running Linux kernels between 6.10 and 6.13 with the `CONFIG_RXGK` option enabled. Common distributions such as Fedora, Arch Linux, and openSUSE Tumbleweed are potentially affected.

## Recommendation

*   Monitor process creations for the execution of binaries without a parent process, as this might indicate exploitation attempts (see "Detect DirtyDecrypt Exploit Execution" Sigma rule).
*   Monitor the execution of `keyctl` for the addition of RXGK keys, as this is a prerequisite for the exploit to work (see "Detect RXGK Key Addition" Sigma rule).
*   Upgrade to a patched Linux kernel version where CVE-2026-31635 is resolved.
*   Disable the `CONFIG_RXGK` option in the kernel configuration if `rxrpc` functionality is not required.
