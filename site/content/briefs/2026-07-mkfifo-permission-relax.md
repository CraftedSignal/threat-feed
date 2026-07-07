---
title: 'mkfifo: permissions of an existing file are changed after FIFO creation fails'
slug: 2026-07-mkfifo-permission-relax
description: 'A vulnerability (CVE-2026-35341) exists in the `uu_mkfifo` utility of `uutils coreutils`, affecting versions prior to 0.6.0. When `mkfifo()` fails because the target file already exists, the utility incorrectly proceeds to modify the permissions of the pre-existing file to `0644`. This can inadvertently relax permissions on sensitive owner-only files, such as SSH private keys, making them accessible to other users on the system and potentially enabling unauthorized access or information disclosure. The issue has been patched in PR #10376.'
date: "2026-07-06T21:56:23Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:uutils:coreutils:-:*:*:*:*:rust:*:*
tags:
  - vulnerability
  - linux
  - coreutils
  - permissions
  - information-disclosure
  - privilege-escalation
vendors:
  - uutils
products:
  - uu_mkfifo (< 0.6.0)
  - uutils coreutils
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: relax permissions on sensitive owner-only files such as SSH private keys, exposing them to other users.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
    evidence: changes the permissions of the pre-existing file to the default FIFO mode (0o666 & umask -> 0644).
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: relax permissions on sensitive owner-only files such as SSH private keys, exposing them to other users.
    confidence_band: high
cves:
  - id: CVE-2026-35341
    cvss: 7.1
    epss: 0.00165
references:
  - https://github.com/advisories/GHSA-pmf6-rcx4-v53v
  - https://github.com/uutils/coreutils/issues/10020
---

A critical vulnerability (CVE-2026-35341) has been identified in `uu_mkfifo`, a utility within `uutils coreutils`, affecting all versions prior to 0.6.0. The flaw, reported by Zellic during a security assessment for Canonical, occurs when `mkfifo()` is invoked on a path that already exists as a regular file. Instead of simply reporting an error and exiting, the `uu_mkfifo` utility inadvertently proceeds to call `fs::set_permissions` on the pre-existing file. This action modifies the file's permissions to the default FIFO mode (typically `0644`), effectively relaxing previously strict access controls. This vulnerability enables an attacker with local access to inadvertently or maliciously expose sensitive, owner-only files, such as SSH private keys, to other users on the system, leading to unauthorized information disclosure and potential privilege escalation. The issue has been acknowledged and a fix implemented in PR #10376.

## Attack Chain

1. An attacker gains local access to a Linux system running an affected version of `uutils coreutils` (`uu_mkfifo` < 0.6.0).
2. The attacker identifies a sensitive file with highly restricted permissions, such as an SSH private key (`~/.ssh/id_rsa`), which is typically set to `0600` or `0400`.
3. The attacker attempts to create a FIFO (named pipe) using the vulnerable `uu_mkfifo` utility, specifying the path of the sensitive file as the target (e.g., `uu_mkfifo ~/.ssh/id_rsa`).
4. The `mkfifo()` system call invoked by `uu_mkfifo` fails because a file with the specified name (`~/.ssh/id_rsa`) already exists.
5. Due to a logical error (missing `continue;` statement after the error handling), `uu_mkfifo` incorrectly proceeds to invoke `fs::set_permissions` on the existing sensitive file.
6. The file's permissions are subsequently changed from their strict original setting (e.g., `0600`) to the default FIFO creation permissions (e.g., `0644`).
7. The sensitive file, now with relaxed permissions, becomes readable by other unprivileged users on the system.
8. Other users or processes can now read the contents of the sensitive file (e.g., the SSH private key), leading to unauthorized information disclosure or further credential compromise.

## Impact

The successful exploitation of CVE-2026-35341 can lead to significant information disclosure and potential privilege escalation on affected Linux systems. An attacker, or even an unsuspecting user, can inadvertently relax file permissions on critical owner-only files, such as SSH private keys, API keys, or configuration files containing credentials. If these files are exposed, unauthorized users could read their contents, enabling lateral movement within the network, unauthorized access to systems, or further credential harvesting. While no specific victim count or targeted sectors have been reported for active exploitation, the coreutils package is fundamental, making a wide range of Linux environments potentially vulnerable.

## Recommendation

*   Immediately patch `uutils coreutils` to version 0.6.0 or later to remediate CVE-2026-35341.
*   Implement file integrity monitoring (FIM) for sensitive files (e.g., SSH keys, `/etc/shadow`, API keys) to detect unexpected permission changes, which may be logged via `file_event` category logs.
*   Review process creation logs for `uu_mkfifo` executions (`process_creation` category) targeting existing sensitive files and investigate any subsequent unauthorized permission modifications.
