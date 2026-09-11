---
title: 'CVE-2026-57842: Kernel Use-After-Free in NetBSD COMPAT_NETBSD32 Layer'
slug: 2026-09-netbsd-uaf
description: A use-after-free and double-free vulnerability in the NetBSD kernel's COMPAT_NETBSD32 layer allows local users to trigger memory corruption or kernel panics via crafted recvmsg system calls.
date: "2026-09-11T15:13:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:netbsd:netbsd:*:*:*:*:*:*:*:*
tags:
  - kernel
  - vulnerability
  - privilege-escalation
vendors:
  - NetBSD
products:
  - NetBSD
affected_os:
  - NetBSD
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This flaw allows local users to cause kernel panics or potential memory corruption, which could lead to privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-57842
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57842
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory systems running 64-bit NetBSD and verify status of COMPAT_NETBSD32
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects 64-bit systems with COMPAT_NETBSD32 enabled.
  mitigation_plan:
    - priority: immediate
      action: Disable COMPAT_NETBSD32 on internet-facing or high-value systems if 32-bit support is not required.
      owner: IT Operations
      addresses: CVE-2026-57842
      evidence: Vulnerability exists within COMPAT_NETBSD32 layer.
---

CVE-2026-57842 is a critical vulnerability within the COMPAT_NETBSD32 compatibility layer of the NetBSD kernel. The issue originates in the msg_recv_copyin() function, where a missing return statement on the success path causes the kernel to retain a reference to an iovec buffer that has already been freed. When a local attacker executes a 32-bit binary on a 64-bit NetBSD system, they can invoke the recvmsg() system call with a msg_iovlen value set between 9 and IOV_MAX. This sequence triggers the kernel to access the previously freed iovec buffer and subsequently attempt to free the same memory allocation a second time. This memory corruption vulnerability represents a significant risk for local privilege escalation and system instability, as it allows for controlled disruption of kernel memory management.

## Impact

Successful exploitation of this vulnerability allows an unprivileged local user to trigger kernel panics, causing denial of service. Furthermore, the memory corruption primitive provides a pathway for local privilege escalation, potentially allowing a standard user to gain administrative control over the affected system. The vulnerability specifically affects 64-bit NetBSD environments that have the COMPAT_NETBSD32 compatibility layer enabled.

## Recommendation

Detection and mitigation should focus on identifying unauthorized execution of 32-bit binaries or suspicious kernel behavior.
* Audit systems for the presence and necessity of the COMPAT_NETBSD32 compatibility layer and disable if not required for legacy support.
* Monitor for unexpected system calls or frequent kernel-level crashes associated with 32-bit binary execution.
* Patch the NetBSD kernel immediately once the vendor provides the security update addressing CVE-2026-57842.
