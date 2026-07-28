---
title: CRIU Restartable Sequences Vulnerability Allows Container Privilege Escalation
slug: 2026-07-criu-rseq-privesc
description: A flaw, CVE-2026-18107, in CRIU's handling of restartable sequences (rseq) during checkpoint/restore allows a malicious process inside a container to hijack CRIU's parasite code injection, enabling the spoofing of process credentials in the checkpoint image and leading to elevated capabilities and zeroed UIDs/GIDs upon restore.
date: "2026-07-28T19:22:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container-security
  - privilege-escalation
  - linux
  - cloud-native
vendors:
  - Red Hat
products:
  - CRIU
  - OpenShift
  - Podman
  - Kubelet
affected_os:
  - RHEL 9
  - RHEL 10
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A malicious process inside a container can register an rseq critical section that hijacks CRIU's parasite code injection during checkpoint, allowing it to spoof the process credentials saved in the checkpoint image. On restore, the container process gains elevated capabilities and zeroed UIDs/GIDs.
    confidence_band: high
cves:
  - id: CVE-2026-18107
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18107
---

A significant vulnerability, CVE-2026-18107, has been identified in CRIU's mechanism for handling restartable sequences (rseq) during checkpoint/restore operations. This flaw allows a malicious process executing within a container to exploit the checkpointing process itself. By registering a specially crafted rseq critical section, an attacker can hijack CRIU's parasite code injection, which occurs during a checkpoint. This manipulation enables the attacker to spoof the process credentials, including capabilities and user/group IDs, stored within the checkpoint image. When the container is subsequently restored from this compromised image, the malicious process inherits these falsified, elevated credentials, resulting in a privilege escalation within the container environment. While severe, the practical impact on Red Hat products like OpenShift and Podman is mitigated by several factors, including the requirement for root or cluster-admin privileges to initiate checkpoint/restore, default user namespaces, SELinux enforcement, persistent seccomp filters, and kernel mount namespace ownership checks in RHEL 9/10 kernels.

## Attack Chain

1. **Initial Access:** An attacker gains initial execution within a container, typically as a non-privileged user.
2. **CRIU Prerequisite Met:** The attacker (or an operator with elevated host privileges, e.g., root for Podman or cluster-admin for OpenShift) initiates a checkpoint operation on the target container using CRIU.
3. **Malicious rseq Registration:** The attacker's process within the container registers an `rseq` critical section designed to intercept and manipulate CRIU's internal functions.
4. **Parasite Code Hijack:** During the checkpoint phase, CRIU attempts to inject its parasite code into the target process. The previously registered malicious `rseq` critical section hijacks this injection.
5. **Credential Spoofing:** The hijacked parasite code is then manipulated to forge and overwrite the process credentials (such as UIDs, GIDs, and capabilities) that CRIU normally saves into the checkpoint image.
6. **Checkpoint Image Corruption:** The corrupted checkpoint image, containing the falsified process credentials, is saved.
7. **Restore Operation:** A restore operation is performed, using the compromised checkpoint image, to restart the container.
8. **Privilege Escalation:** Upon successful restoration, the container process resumes execution with the spoofed, elevated capabilities and zeroed UIDs/GIDs, effectively achieving privilege escalation within the container.

## Impact

Successful exploitation of CVE-2026-18107 directly leads to privilege escalation within containerized environments. An attacker, initially operating with limited privileges inside a container, can gain elevated capabilities and zeroed UIDs/GIDs upon restore, potentially granting them near-root access within that container. While the vulnerability itself is critical, its practical impact on Red Hat products is significantly limited by multiple security layers. These mitigations include the requirement of root or cluster-admin privileges to trigger checkpoint/restore operations, OpenShift's default enforcement of user namespaces (which scopes capabilities), SELinux type enforcement, persistent seccomp filters, and kernel mount namespace ownership checks on RHEL 9/10, all of which aim to prevent container escapes or broad privilege escalations even if the initial credential spoofing occurs.

## Recommendation

* If deploying CRIU in environments without the mitigations present in Red Hat products, immediately review and implement security controls that restrict checkpoint/restore operations to highly trusted administrators.
* Ensure that container orchestration platforms, such as OpenShift, are configured with default user namespaces and robust RBAC policies that prevent non-administrative users from initiating checkpoint/restore operations, thereby mitigating the risk described in CVE-2026-18107.
* Verify that SELinux policies are enforced in containerized environments to block unauthorized privilege transitions, even if capabilities are spoofed, as this provides a critical layer of defense against CVE-2026-18107.
* Confirm that `seccomp` filters are active and persist through checkpoint/restore operations, as these can restrict syscalls and prevent exploitation attempts associated with CVE-2026-18107.
