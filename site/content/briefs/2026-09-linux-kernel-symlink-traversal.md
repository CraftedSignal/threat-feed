---
title: Local Privilege Escalation via Linux Kernel X-mount.subdir Symlink Traversal
slug: 2026-09-linux-kernel-symlink-traversal
description: A local privilege escalation vulnerability in the Linux kernel (6.15+) allows unprivileged users to bypass filesystem boundary restrictions during mount operations via the X-mount.subdir option.
date: "2026-09-02T17:15:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*
vendors:
  - Linux Foundation
products:
  - Linux Kernel (>= 6.15)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.
    confidence_band: high
cves:
  - id: CVE-2026-78409
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78409
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch kernel to the latest non-vulnerable version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-78409 mitigation
  mitigation_plan:
    - priority: immediate
      action: Review /etc/fstab and remove non-essential user-mount permissions
      owner: IT Operations
      addresses: CVE-2026-78409
      evidence: The vulnerability requires fstab-authorized mount entry
---

A security vulnerability exists in the Linux kernel (version 6.15 and later) related to the implementation of the X-mount.subdir mount option. When an unprivileged user with fstab-authorized mounting permissions initiates a mount, the kernel utilizes a detached-tree fast path and passes the subdirectory path to the open_tree() system call with the AT_SYMLINK_NOFOLLOW flag. This implementation is insufficient because the flag fails to prevent intermediate symlink traversal or enforce strict path resolution boundaries within the newly mounted filesystem. Consequently, a local attacker can exploit this flaw to mount arbitrary host paths at designated mountpoints, resulting in unauthorized filesystem access and potential privilege escalation. This issue highlights a gap in kernel-level validation of mount paths when utilizing the fast-path mount mechanism.

## Attack Chain

1. An attacker identifies a system with an entry in /etc/fstab that allows an unprivileged user to mount a filesystem using the X-mount.subdir option.
2. The attacker creates a malicious symlink in a directory under their control that points to a sensitive host filesystem location.
3. The attacker executes the mount command referencing the fstab entry, specifying the malicious path as the subdirectory.
4. The kernel enters the detached-tree fast path for the mount operation.
5. The open_tree() function is called with the AT_SYMLINK_NOFOLLOW flag.
6. Due to the vulnerability, the kernel follows the intermediate symlinks, bypassing the intended path restrictions.
7. The sensitive host path is mounted at the attacker's chosen mountpoint.
8. The attacker accesses the newly mounted sensitive files, enabling further exploitation or privilege escalation.

## Impact

Successful exploitation allows a local unprivileged user to gain unauthorized access to sensitive files or directories outside their intended scope. In environments where unprivileged users are granted mount permissions via fstab, this vulnerability significantly undermines filesystem isolation. The impact is restricted to local systems running vulnerable Linux kernel versions (6.15 and later).

## Recommendation

1. Patch the Linux kernel to the latest version provided by the distribution vendor to address the open_tree() handling logic in CVE-2026-78409.
2. Audit /etc/fstab entries to identify and restrict unprivileged users who currently possess 'user' or 'users' mount options.
3. Monitor system audit logs for abnormal mount events and mount operations involving symlinks.
