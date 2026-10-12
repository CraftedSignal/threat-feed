---
title: Local Privilege Escalation via Out-of-Bounds Write in Linux Kernel FUSE readdir
slug: 2026-10-linux-fuse-oob
description: CVE-2026-31694 is an out-of-bounds write vulnerability in the Linux kernel FUSE readdir implementation that allows local attackers to corrupt physically adjacent memory pages and achieve privilege escalation.
date: "2026-10-12T18:29:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:7.1:*:*:*:*:*:*:*
tags:
  - linux
  - kernel
  - privilege-escalation
  - fuse
vendors:
  - Linux Foundation
products:
  - Linux Kernel (< 6.6.136, 6.12.84, 6.18.25, 7.0.2, 7.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This repository contains a marker PoC for the write primitive and local privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-31694
    cvss: 7.8
    epss: 0.00173
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XCYBERSTAN-CVE-2026-31694-POC
  - https://cyberstan.co.uk/fuse-readdir-oob/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Linux kernels to patched versions.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-31694 requires kernel update to fixed version.
  mitigation_plan:
    - priority: immediate
      action: Restrict unprivileged FUSE mounts.
      owner: IT Operations
      addresses: CVE-2026-31694
      evidence: Source document indicates exploitation requires FUSE interaction.
---

CVE-2026-31694 is an out-of-bounds write vulnerability identified in the Linux kernel's FUSE (Filesystem in Userspace) readdir implementation, specifically within `fs/fuse/readdir.c`. The flaw occurs in `fuse_add_dirent_to_cache()` due to improper bounds checking. An attacker-controlled FUSE server can provide a dirent with a name length of 4095 bytes, which, when serialized, results in a 4120-byte record. The kernel attempts to copy this into a 4096-byte page cache, causing a 24-byte overwrite of the immediately following physical memory page.

This vulnerability affects Linux kernel versions 6.15 through 7.1. A proof-of-concept (PoC) exploit has been published, demonstrating how to use this primitive to corrupt filesystem cache entries, such as `/etc/passwd`. By modifying the root entry to remove the password requirement, a local attacker can gain root privileges. The issue was addressed in the Linux kernel via commit `51a8de6c50bf9`.

## Attack Chain

1. Attacker establishes a malicious FUSE server on the target Linux system.
2. Attacker interacts with the mount point to trigger a readdir operation.
3. Malicious FUSE server returns a crafted dirent with a `namelen` of 4095.
4. Kernel `fuse_add_dirent_to_cache` processes the dirent and performs a memory copy that exceeds the allocated page boundary by 24 bytes.
5. Attacker uses memory grooming (e.g., exhausting PCP free page lists) to ensure a target page, such as a cached version of `/etc/passwd`, is placed physically adjacent to the FUSE cache page.
6. The 24-byte overwrite corrupts the target page memory.
7. Attacker triggers a read of the corrupted file or process to utilize the modified data.
8. Final objective is achieved: execution of privileged commands via modified root credentials (e.g., `su -s /bin/sh root`).

## Impact

Successful exploitation allows a local user with low privileges to escalate to root access on affected systems. This bypasses standard authentication and integrity controls by directly manipulating kernel-space memory representations of sensitive files. The exploit is probabilistic and poses a risk of system instability, kernel panics, or non-target memory corruption if the memory grooming fails to place the victim page correctly.

## Recommendation

* Patch all Linux kernel instances immediately; apply updates to versions >= 6.6.136, 6.12.84, 6.18.25, 7.0.2, or 7.1 where the fix for CVE-2026-31694 is integrated.
* Restrict the ability of unprivileged users to mount FUSE filesystems if not required for the specific workload.
* Monitor for the use of custom or unexpected FUSE mounts using system auditing tools (e.g., checking `mount` logs or `/proc/mounts`).
* Audit for local processes performing unusual memory grooming activities or utilizing FUSE-related system calls in a suspicious manner.
