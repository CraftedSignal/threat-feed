---
title: Amazon Firecracker Virtio PCI Out-of-Bounds Write Vulnerability (CVE-2026-5747)
slug: 2026-04-firecracker-oob-write
description: An out-of-bounds write vulnerability in Amazon Firecracker's virtio PCI transport (CVE-2026-5747) allows a local guest user with root privileges to potentially crash the VMM process or execute arbitrary code on the host.
date: "2026-04-08T00:16:05Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5747
  - firecracker
  - out-of-bounds write
  - vmm
  - virtio
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5747
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5747
rules:
  - title: Firecracker VMM Process Crash
    description: Detects crashes of the Firecracker VMM process, which could be indicative of CVE-2026-5747 exploitation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Modification of Virtio Devices
    description: Detects potentially malicious processes attempting to configure or modify virtio devices within a Firecracker guest, potentially related to CVE-2026-5747.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Kernel Module Loading in Guest OS
    description: Detects loading of kernel modules within the guest OS which might indicate preparation for exploitation with custom kernel
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

CVE-2026-5747 is an out-of-bounds write vulnerability affecting the virtio PCI transport implementation in Amazon Firecracker versions 1.13.0 through 1.14.3 and 1.15.0, specifically on x86_64 and aarch64 architectures. This vulnerability could be exploited by a malicious local guest user who has gained root privileges within the guest operating system. Successful exploitation could lead to a denial-of-service condition by crashing the Firecracker Virtual Machine Monitor (VMM) process. In scenarios where specific preconditions are met, such as the usage of a custom guest kernel or particular snapshot configurations, this vulnerability can also potentially lead to arbitrary code execution on the host system. Defenders should upgrade to Firecracker versions 1.14.4 or 1.15.1 or later to remediate the issue.

## Attack Chain

1.  Attacker gains root privileges within a Firecracker guest OS.
2.  Attacker identifies the Firecracker VMM version running on the host, confirming it is within the vulnerable range (1.13.0 - 1.14.3 or 1.15.0).
3.  The attacker modifies virtio queue configuration registers after device activation. This is the trigger point for the vulnerability, exploiting the out-of-bounds write.
4.  The crafted write operation corrupts memory within the Firecracker VMM process.
5.  If the memory corruption is limited, this may cause a denial-of-service by crashing the VMM process.
6.  If specific preconditions are met (custom guest kernel, specific snapshot configurations), the memory corruption allows for arbitrary code execution.
7.  The attacker executes malicious code within the context of the Firecracker VMM process on the host.
8.  The attacker achieves persistence or performs further malicious actions on the host system.

## Impact

Successful exploitation of CVE-2026-5747 can lead to a denial-of-service condition, disrupting the services hosted on affected Firecracker instances. In certain circumstances, this vulnerability can escalate to arbitrary code execution on the host, potentially compromising the entire system and any other virtual machines hosted on it. This can lead to data breaches, system instability, and complete loss of control over the compromised host. The severity is dependent on the environment configuration and the attacker's capabilities, ranging from service disruption to full host compromise.

## Recommendation

*   Upgrade all Firecracker installations to versions 1.14.4 or 1.15.1 or later to patch CVE-2026-5747, as recommended by the vendor.
*   Monitor Firecracker guest OS instances for unauthorized attempts to modify virtio queue configuration registers to detect potential exploitation attempts related to CVE-2026-5747.
*   Implement strict access control policies within the guest operating systems to minimize the risk of attackers gaining root privileges, thus reducing the attack surface for CVE-2026-5747.
