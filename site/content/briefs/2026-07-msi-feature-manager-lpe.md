---
title: CVE-2026-57851 — MSI Feature Manager Kernel Driver Local Privilege Escalation
slug: 2026-07-msi-feature-manager-lpe
description: A local privilege escalation vulnerability (CVE-2026-57851) exists in the MSI Feature Manager's KernCoreLib64.sys kernel driver that allows any local user to perform arbitrary physical memory read/write and unrestricted I/O port operations by accessing exposed IOCTL handlers without requiring administrator privileges, enabling manipulation of kernel objects, tampering with kernel-mode callbacks, bypassing Protected Process Light, and disabling security software.
date: "2026-07-07T17:24:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - windows
  - driver-vulnerability
vendors:
  - MSI
products:
  - MSI Feature Manager
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local privilege escalation vulnerability in the KernCoreLib64.sys kernel driver that allows any locally logged-on user to perform arbitrary physical memory read/write and unrestricted I/O port operations by accessing exposed IOCTL handlers without administrator privileges.
    confidence_band: high
cves:
  - id: CVE-2026-57851
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57851
---

A critical local privilege escalation (LPE) vulnerability, identified as CVE-2026-57851, has been discovered in the MSI Feature Manager software, specifically within its `KernCoreLib64.sys` kernel driver. This flaw enables any locally logged-on user to achieve SYSTEM-level privileges without requiring administrative credentials. The vulnerability stems from inadequately protected IOCTL handlers that grant direct access to arbitrary physical memory read/write operations and unrestricted I/O port access. Attackers can leverage these capabilities to directly interact with kernel objects, bypass Windows' Protected Process Light (PPL) mechanisms, disable installed security software, and manipulate kernel-mode callbacks, ultimately leading to a full compromise of the affected system. This vulnerability poses a significant risk to the integrity and security of systems running MSI Feature Manager, as it allows for complete control by a low-privileged local attacker.

## Attack Chain

1.  **Local User Execution**: A malicious application or script, executed by a standard local user on an affected Windows system, initiates the exploitation process.
2.  **Driver Interface Interaction**: The malicious code attempts to interact with the `KernCoreLib64.sys` kernel driver's exposed device interface.
3.  **IOCTL Handler Access**: The attacker successfully opens a handle to the driver's device object and invokes specific, inadequately protected IOCTL (I/O Control) handlers.
4.  **Arbitrary Memory/I/O Operations**: Through these vulnerable IOCTL handlers, the driver grants the attacker arbitrary physical memory read/write access and unrestricted I/O port operations, typically reserved for kernel-mode processes.
5.  **Kernel Object Manipulation**: The attacker uses these powerful primitives to manipulate sensitive kernel objects, modify kernel-mode data structures, or tamper with critical system callbacks.
6.  **Security Feature Bypass**: Leveraging kernel manipulation, the attacker bypasses Windows security mechanisms, such as Protected Process Light (PPL), which normally safeguards critical system processes.
7.  **Security Software Disablement**: The attacker then utilizes their elevated kernel access to disable or tamper with installed endpoint security software, removing detection and prevention capabilities.
8.  **Privilege Escalation**: With security measures bypassed and kernel control established, the attacker achieves SYSTEM-level privileges, gaining complete control over the compromised operating system.

## Impact

The successful exploitation of CVE-2026-57851 can lead to a complete compromise of an affected Windows system. Any local user, regardless of their default privileges, can elevate their access to SYSTEM, granting them full control over the operating system. This allows an attacker to install persistent malware, access or exfiltrate sensitive data, disable or tamper with security solutions, and establish backdoors. While no specific victim count or targeted sectors are mentioned, any organization or individual utilizing MSI Feature Manager on their Windows endpoints is susceptible, as the vulnerability is accessible to any locally authenticated user. The impact is severe, potentially leading to data breaches, system integrity loss, and further lateral movement within a compromised network.

## Recommendation

*   Prioritize patching for CVE-2026-57851 on all systems running MSI Feature Manager immediately as recommended by the vendor.
