---
title: Linux Kernel SCTP Use-After-Free Vulnerability (CVE-2026-64564)
slug: 2026-08-sctp-uaf-lpe
description: A Use-After-Free vulnerability in the Linux kernel SCTP subsystem (CVE-2026-64564) allows local unprivileged users to escalate privileges to root through malicious ASCONF chunk processing.
date: "2026-08-19T13:36:43Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - Linux kernel (6.12.95)
affected_os:
  - Debian 13
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The exploit leverages that Use-After-Free (UAF) condition to... call commit_creds() to escalate privileges to root.
    confidence_band: high
cves:
  - id: CVE-2026-64564
    cvss: 9.8
    epss: 0.00476
references:
  - https://sploitus.com/exploit?id=B10CF7EF-E197-5ED4-BD0F-7846C5CA3F6E
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch kernel to 6.12.101 or higher
      owner: IT Operations
      due: 48h
      evidence: Fix commit confirmed in kernel 6.12.101
  mitigation_plan:
    - priority: immediate
      action: Unload SCTP kernel module
      owner: IT Operations
      addresses: CVE-2026-64564
      evidence: Author recommended mitigation for production systems
---

CVE-2026-64564 is a high-severity Use-After-Free (UAF) vulnerability discovered in the Linux kernel's SCTP (Stream Control Transmission Protocol) subsystem. The flaw is triggered when the kernel processes a malformed `ASCONF` (Address Configuration) chunk containing `DEL-IP` (Delete IP Address) parameters. This action causes the kernel to improperly free the `struct sctp_transport` memory object while retaining a dangling pointer to it. 

The vulnerability affects various Linux kernel versions, including 6.12.95, and has been addressed in upstream kernel versions 6.12.101 and 6.6.148. A Proof of Concept (PoC) titled "SCTPhantom" is publicly available, detailing how an attacker can leverage this UAF condition to perform a heap spray, bypass Kernel Address Space Layout Randomization (KASLR), and corrupt the `struct cred` of a process to escalate privileges to root. Due to the requirement for hardcoded kernel offsets in the available PoC, exploitation currently requires specific knowledge of the target kernel build.

## Attack Chain

1. The attacker verifies that the SCTP module is loaded on the target Linux system via `lsmod`.
2. The attacker establishes a valid SCTP association by running an auxiliary listener process on the victim host or an external peer.
3. The attacker executes the exploit binary as a non-privileged user to trigger the SCTP `ASCONF` command.
4. The malformed `ASCONF` chunk containing `DEL-IP` is processed, resulting in the premature freeing of `struct sctp_transport`.
5. The attacker executes a heap spray to reclaim the freed memory region with attacker-controlled data.
6. The attacker leaks kernel addresses via the dangling pointer to calculate and bypass KASLR offsets.
7. The attacker overwrites the target process's `struct cred` by manipulating the corrupted kernel memory.
8. The exploit invokes `commit_creds()` to escalate the process privileges to root and spawns an interactive shell.

## Impact

Successful exploitation of CVE-2026-64564 results in total local privilege escalation on vulnerable Linux systems. An attacker with standard user access can gain full root control, enabling unauthorized access to sensitive files like `/etc/shadow`, installation of persistent backdoors, and complete compromise of system integrity. The vulnerability affects any distribution running unpatched kernel versions, with significant risk posed to servers and multi-user environments.

## Recommendation

* Patch all Linux systems to kernels 6.12.101, 6.6.148, or later, which contain the official fix for CVE-2026-64564.
* If patching is not immediately feasible, disable the SCTP module on production systems by running `sudo modprobe -r sctp` and adding it to a blacklist configuration file.
* Implement system-wide kernel hardening and monitor for unusual loading of the `sctp` kernel module on systems where it is not required for business operations.
* Deploy kernel integrity monitoring to detect anomalous memory modifications consistent with UAF heap spraying.
