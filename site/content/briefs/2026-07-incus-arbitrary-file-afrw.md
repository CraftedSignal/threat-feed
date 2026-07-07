---
title: Incus Container Escape via Arbitrary File Read/Write (CVE-2026-48749)
slug: 2026-07-incus-arbitrary-file-afrw
description: A critical vulnerability, CVE-2026-48749, in Incus allows an attacker to achieve arbitrary file read and write on the host filesystem with root privileges by crafting a malicious container image containing a symlink, bypassing validation, and potentially leading to arbitrary command execution.
date: "2026-07-03T10:40:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - container-escape
  - privilege-escalation
  - vulnerability-exploitation
  - linux
vendors:
  - LXC
products:
  - incus (< 7.2.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Container Escape
    evidence: A specially crafted image can be used to read or create/write arbitrary files on the host; possibly leading to arbitrary command execution... In practice, this allows a malicious actor to access the host's filesystem with root privileges.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2q3f-q5pq-g8wv
---

A critical vulnerability, tracked as CVE-2026-48749, has been identified in Incus, a container and VM management system developed by LXC. This flaw enables a malicious actor to achieve arbitrary file read and write capabilities on the host system with root privileges, potentially escalating to full command execution. The vulnerability arises from Incus's handling of specially crafted container images, specifically when a duplicate top-level `rootfs` symlink is present. While Incus initially validates `metadata.yaml` and a normal `rootfs/` entry, it subsequently processes a symlink like `rootfs -> /`, allowing a container's root filesystem to be mapped directly to the host's root. This bypasses container isolation, granting the attacker unauthorized access to the host's underlying filesystem and sensitive files such as `/etc/shadow`, affecting Incus versions prior to 7.2.0.

## Attack Chain

1.  An attacker crafts a malicious Incus image package (`.tar` file) that initially contains a valid `metadata.yaml` and an empty `rootfs/` directory.
2.  The attacker then manipulates the `.tar` archive by removing the legitimate `rootfs/` directory.
3.  A symbolic link named `rootfs` pointing to `/` (the host's root directory) is injected into the archive at the top level.
4.  The malicious image (`afrw-rootfs-symlink.tar`) is imported into a vulnerable Incus instance using `incus image import`.
5.  A new container is initialized from this malicious image using `incus init afrw-rootfs-symlink afrw-rootfs-symlink`.
6.  The attacker uses `incus file pull` commands, targeting paths like `/etc/shadow` from within the created container, to read arbitrary files from the host filesystem.
7.  The attacker uses `incus file push` commands to write or create arbitrary files on the host filesystem.
8.  Successful arbitrary file read/write with root privileges can lead to host compromise, including privilege escalation or arbitrary command execution.

## Impact

Successful exploitation of CVE-2026-48749 leads to arbitrary file read and write on the host system with root privileges. This means an attacker can access any file on the host, including sensitive system configuration files (e.g., `/etc/shadow` for password hashes) or application data. Furthermore, the ability to write arbitrary files allows for planting malicious executables, modifying critical system configurations, or establishing persistence mechanisms. Ultimately, this can lead to full host compromise, enabling arbitrary command execution, data exfiltration, system defacement, or further lateral movement within the compromised environment. The vulnerability impacts organizations utilizing Incus for containerization and could lead to significant data breaches or operational disruption.

## Recommendation

*   Prioritize patching all Incus instances to version 7.2.0 or later immediately to remediate CVE-2026-48749.
*   Review Incus image origins and implement strict controls to prevent the import of untrusted or malicious container images.
*   Monitor Incus server logs for unusual image import attempts or unexpected file operations performed via `incus file` commands originating from newly provisioned containers.
