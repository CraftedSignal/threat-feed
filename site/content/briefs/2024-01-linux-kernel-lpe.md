---
title: Linux Kernel proc_readdir_de() Use-After-Free Local Privilege Escalation
slug: 2024-01-linux-kernel-lpe
description: A local privilege escalation vulnerability exists in the Linux Kernel versions ~3.14+ through 6.18-rc5 due to a use-after-free in the proc_readdir_de() function, where a concurrent traversal can dereference a freed entry's fields during network device unregistration, leading to privilege escalation via modprobe_path overwrite.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - local-privilege-escalation
  - kernel-vulnerability
  - use-after-free
  - linux
vendors:
  - Linux Kernel
products:
  - Linux Kernel
affected_os:
  - Debian Bookworm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-40271
    epss: 0.04037
references:
  - https://www.exploit-db.com/exploits/52550
  - https://nvd.nist.gov/vuln/detail/CVE-2025-40271
  - https://git.kernel.org/linus/895b4c0c79b092d732544011c3cecaf7322c36a1
rules:
  - title: Detect Anomalous d_ino Values in getdents64 Output
    description: Detects potential use-after-free exploitation attempts by monitoring for anomalous d_ino values (kernel heap addresses) in getdents64 output.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect modprobe_path Overwrite
    description: Detects attempts to overwrite the modprobe_path, a common technique for local privilege escalation on Linux.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A local privilege escalation vulnerability, CVE-2025-40271, affects Linux Kernel versions from approximately 3.14 up to 6.18-rc5. The vulnerability lies in the `proc_readdir_de()` function within the kernel's proc filesystem implementation. When a `proc_dir_entry` is removed from the parent's red-black tree, it isn't properly marked as detached, leaving stale rb-links. An attacker can exploit this use-after-free condition to gain elevated privileges on the system by triggering a race condition. This involves calling `getdents64()` on a `/proc` subdirectory, specifically `/proc/self/net/dev_snmp6/`, while concurrently unregistering network devices. Successful exploitation allows an attacker to overwrite the `modprobe_path` for local privilege escalation. The vulnerability was patched in stable versions 5.10.247, 6.1.159, 6.12.73, and 6.18-rc6.

## Attack Chain

1.  The attacker sets up a user namespace with CAP_NET_ADMIN capabilities to manipulate network devices.
2.  The attacker creates multiple veth (virtual ethernet) pairs. These veth pairs populate the `/proc/self/net/dev_snmp6/` directory, which the exploit will target.
3.  The attacker initiates a race condition by calling `getdents64()` on the `/proc/self/net/dev_snmp6/` directory. This reads directory entries from the proc filesystem.
4.  Concurrently with the `getdents64()` call, the attacker triggers the unregistration of network devices. This action removes proc entries, potentially freeing a `proc_dir_entry`.
5.  Due to the vulnerability, the removed `proc_dir_entry` is not properly cleared, leaving stale links in the red-black tree.
6.  The `getdents64()` call encounters the freed `proc_dir_entry` and attempts to dereference its fields, resulting in a use-after-free condition. The attacker sprays the freed kmalloc-192 slots with `msg_msg`.
7.  The attacker extracts a kernel heap address from the leaked `d_ino` field, which is part of the `msg_msg` header.
8.  The extracted kernel heap address is used to calculate the address of `modprobe_path`, and the attacker overwrites it, leading to local privilege escalation.

## Impact

Successful exploitation of this vulnerability allows an unprivileged local attacker to escalate their privileges to root. This can lead to complete system compromise, including data theft, malware installation, and denial of service. While the provided exploit shows a hit rate of 40-60% per attempt and may require several attempts, the impact is significant due to the potential for full system control. This vulnerability affects a wide range of Linux kernel versions and could impact numerous systems if left unpatched.

## Recommendation

*   Apply the appropriate kernel patch from the Linux Kernel org, specifically commit 895b4c0c79b092d732544011c3cecaf7322c36a1, which adds the `pde_erase()` helper function that calls `RB_CLEAR_NODE()` after `rb_erase()`.
*   Monitor for anomalous `d_ino` values in `getdents64` output, as indicated in the exploit description, which are indicative of a UAF condition. Deploy the Sigma rule `Detect Anomalous d_ino Values in getdents64 Output` to identify potential exploitation attempts.
*   Implement restrictions on user namespaces and network namespace creation to limit the attack surface, as the exploit requires CAP_NET_ADMIN.
*   Monitor process creation events for unexpected modifications to `modprobe_path`. Use the Sigma rule `Detect modprobe_path Overwrite` to identify attempts to escalate privileges.
*   Review systems for the presence of vulnerable kernel versions (~3.14+ through 6.18-rc5) as detailed in the overview to prioritize patching efforts.
