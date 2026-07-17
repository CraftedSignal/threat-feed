---
title: Incomplete Privilege Drop in 'sh' Package Allows Privilege Escalation
slug: 2026-07-sh-uid-incomplete-privilege-drop
description: A vulnerability in the 'sh' package, affecting Linux/Unix-like systems, allows for an incomplete privilege drop when the `_uid` option is used. When a process with elevated privileges launches a child process with `_uid=<unprivileged user>`, the child process changes its UID and primary GID but fails to reset its supplementary groups. This flaw enables the child process to retain potentially privileged supplementary groups (e.g., root, docker), bypassing intended privilege boundaries and granting access to resources beyond its expected permissions.
date: "2026-07-17T18:44:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - linux
vendors:
  - sh
products:
  - sh (< 2.2.4)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The `_uid` option performed an incomplete privilege drop on Linux/Unix-like systems. When `sh` was run from a process with elevated privileges, such as root, and a command was launched with `_uid=<unprivileged user>`, the child process changed its UID and primary GID but did not reset its supplementary groups.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q38v-wp89-2w55
---

A high-severity vulnerability (CVE-2026-54552) has been identified in the `sh` package, versioned prior to 2.2.4, impacting Linux/Unix-like operating systems. This flaw, dubbed an "incomplete privilege drop," occurs when a process with elevated privileges executes `sh` using the `_uid` option to launch a command as an unprivileged user. While the child `sh` process correctly changes its User ID (UID) and primary Group ID (GID) to that of the specified unprivileged user, it critically fails to drop the supplementary groups inherited from its privileged parent process. This oversight allows the ostensibly unprivileged child process to retain access to resources and permissions associated with potentially privileged supplementary groups, such as `root`, `docker`, `disk`, `shadow`, or `sudo`. This bypasses intended security boundaries, enabling a local attacker to escalate privileges or access restricted files and functionalities, particularly if the `_uid` option was relied upon for privilege separation.

## Attack Chain

1. An attacker gains initial access to a Linux/Unix-like system with some level of user privileges.
2. The attacker identifies a privileged process (e.g., a system service, a script executed by root) that utilizes the `sh` package and its `_uid` option to execute commands.
3. The privileged parent process executes a command via `sh` with `_uid=<unprivileged user>`, intending to restrict the command's execution context.
4. The `sh` package initiates a child process, which correctly changes its User ID (UID) and primary Group ID (GID) to that of the specified unprivileged user.
5. Due to the vulnerability, the child process does not fully reset its supplementary group list and inherits some or all of the privileged supplementary groups from the parent process.
6. The attacker, operating within the context of this unprivileged child process, can now leverage the retained privileged supplementary groups to access files or resources that would normally be inaccessible to the unprivileged user.
7. This allows the attacker to escalate privileges or perform actions beyond the intended scope of the unprivileged user, potentially leading to full system compromise.

## Impact

The vulnerability allows for local privilege escalation on Linux/Unix-like systems where the `sh` package (versions prior to 2.2.4) is used in conjunction with the `_uid` option from a privileged parent process. Organizations that deploy applications or services relying on `_uid` for privilege separation are directly impacted. An attacker exploiting this flaw can gain unauthorized access to sensitive files, directories, or system functions by inheriting privileged supplementary groups such as `root`, `docker`, `shadow`, or `sudo`. This subversion of privilege boundaries can lead to data exfiltration, system compromise, or further lateral movement within the network. There is no specific number of victims or targeted sectors mentioned, but any environment utilizing the vulnerable `sh` package in this manner is at risk.

## Recommendation

* Upgrade the `pip/sh` package to version 2.2.4 or newer to patch CVE-2026-54552 immediately.
* As a workaround, avoid using the `_uid` option in the `sh` package when the intended user is a less-privileged user and the parent process has elevated privileges, until the patch can be applied.
