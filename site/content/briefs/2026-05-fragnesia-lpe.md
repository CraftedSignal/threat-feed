---
title: 'Fragnesia: Linux Kernel Local Privilege Escalation via ESP-in-TCP'
slug: 2026-05-fragnesia-lpe
description: A new local privilege escalation vulnerability in the Linux kernel's XFRM ESP-in-TCP subsystem, named "Fragnesia," allows unprivileged local attackers to modify read-only file contents in the kernel page cache and achieve root privileges through a deterministic page-cache corruption.
date: "2026-05-13T13:08:45Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - kernel
vendors:
  - Wiz
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.wiz.io/blog/fragnesia-linux-kernel-local-privilege-escalation-via-esp-in-tcp
rules:
  - title: Detect Suspicious esp4/esp6/rxrpc Module Unloading
    description: Detects the unloading of esp4, esp6, or rxrpc kernel modules, which could indicate an attempt to mitigate the Fragnesia or DirtyFrag vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - system
      - linux
  - title: Detect Modification of /usr/bin/su in Page Cache
    description: Detects potential exploitation of Fragnesia by monitoring for writes to the /usr/bin/su binary, even if the changes only occur in the page cache.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Researchers have disclosed a new variant in the DirtyFrag family of Linux local privilege escalation (LPE) vulnerabilities, named “Fragnesia.” This vulnerability impacts the Linux kernel’s XFRM ESP-in-TCP subsystem. It allows unprivileged local attackers to modify read-only file contents in the kernel page cache and achieve root privileges through a deterministic page-cache corruption primitive. According to the researcher who discovered Dirty Frag, Hyunwoo Kim, Fragnesia emerged as an unintended side effect of one of the patches addressing the original Dirty Frag vulnerabilities. Usage of AppArmor restrictions on unprivileged user namespaces may serve as a partial mitigation, but unlike DirtyFrag, no host-level privileges are required.

## Attack Chain

1.  Attacker gains initial access to a system running a vulnerable Linux kernel.
2.  Attacker creates user and network namespaces to gain CAP_NET_ADMIN privileges within an isolated namespace.
3.  The attacker installs a crafted ESP security association through NETLINK_XFRM.
4.  File-backed pages are spliced into a TCP receive queue before the socket transitions into espintcp ULP mode.
5.  ESP processing is enabled, triggering in-place decryption of queued data by the kernel.
6.  This decryption process causes controlled corruption of the underlying page cache through AES-GCM keystream manipulation.
7.  The attacker repeatedly triggers controlled single-byte writes into cached file pages.
8.  The attacker overwrites the first bytes of /usr/bin/su with a small ELF payload that invokes setresuid(0,0,0) and executes /bin/sh, resulting in a root shell. The modification exists only in page cache memory and does not alter the on-disk binary.

## Impact

Successful exploitation of Fragnesia allows an unprivileged local attacker to gain root privileges on a vulnerable Linux system. This could lead to complete system compromise, data theft, and denial of service. The vulnerability targets the core kernel functionality, affecting a broad range of Linux distributions and potentially impacting a large number of systems. The exploit overwrites the /usr/bin/su binary in memory to achieve root access.

## Recommendation

*   Apply vendor kernel patches that address the underlying XFRM ESP-in-TCP vulnerability as they become available.
*   Until patches are deployed, disable the vulnerable modules for both Fragnesia and DirtyFrag by running `rmmod esp4 esp6 rxrpc` and configuring module blocking via `/etc/modprobe.d/fragnesia.conf` as described in the overview.
*   Restrict or disable unprivileged user namespaces where operationally feasible to limit the attack surface, as mentioned in the overview.
*   Monitor systems for suspicious namespace creation, XFRM manipulation, or abnormal use of AF_ALG, as mentioned in the advisory.
