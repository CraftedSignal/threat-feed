---
title: Local Privilege Escalation in Ubuntu Kernel via OverlayFS
slug: 2026-08-ubuntu-overlayfs-lpe
description: Publicly available proof-of-concept exploits targeting CVE-2023-2640 and CVE-2023-32629 allow unprivileged users to gain root access on Ubuntu systems by bypassing permission checks in the overlayfs subsystem.
date: "2026-08-28T00:20:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:o:canonical:ubuntu_linux:23.04:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - kernel
  - overlayfs
vendors:
  - Canonical
products:
  - Ubuntu
affected_os:
  - Ubuntu 23.04
  - Ubuntu 22.10
  - Ubuntu 22.04 LTS
  - Ubuntu 18.04 LTS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An unprivileged user can leverage these flaws to set privileged extended attributes on files, leading to full root access on the affected system.
    confidence_band: high
cves:
  - id: CVE-2023-2640
    cvss: 7.8
    epss: 0.16052
  - id: CVE-2023-32629
    cvss: 7.8
    epss: 0.10362
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-2640
  - https://nvd.nist.gov/vuln/detail/CVE-2023-32629
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch kernel vulnerabilities CVE-2023-2640 and CVE-2023-32629 across all Ubuntu instances.
      owner: IT Operations
      due: 48h
      evidence: Publicly available exploits increase risk of active exploitation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade kernel to a patched version provided by Canonical.
      owner: IT Operations
      addresses: CVE-2023-2640, CVE-2023-32629
      evidence: Vendor patch availability.
---

Researchers have released multiple proof-of-concept (PoC) exploits targeting two linked local privilege escalation vulnerabilities in the Ubuntu kernel, identified as CVE-2023-2640 and CVE-2023-32629. These vulnerabilities stem from improper permission handling within the overlayfs (Overlay File System) implementation. Specifically, the kernel fails to perform adequate security checks when setting extended attributes (xattrs) on files using 'trusted.overlayfs.*'. 

An unprivileged local user can exploit these flaws by mounting a manipulated overlay file system, allowing them to set privileged extended attributes. This action bypasses standard kernel security mechanisms and enables the escalation of privileges to root. The vulnerabilities affect various Ubuntu releases, including 23.04, 22.10, 22.04 LTS, and 18.04 LTS, depending on the specific kernel version in use (notably 5.4.0, 5.19.0, and 6.2.0). Given the availability of weaponized PoC code on public platforms, the likelihood of exploitation by local attackers is high.

## Impact

Successful exploitation of these vulnerabilities allows an attacker with low-privilege local access to gain full administrative (root) control over the host system. This facilitates arbitrary code execution, complete system compromise, data exfiltration, and persistent access. All Ubuntu environments running vulnerable kernel versions are at risk if local access to the system is possible.

## Recommendation

* Prioritize patching the kernel on all affected Ubuntu systems. Consult official Canonical security bulletins for the specific kernel packages addressing these CVEs.
* Monitor for the execution of unauthorized shell scripts or binaries from temporary directories, which is the observed delivery mechanism for the published PoC.
* Restrict local access and enforce the principle of least privilege to minimize the potential for exploitation by unauthenticated or low-privilege users.
