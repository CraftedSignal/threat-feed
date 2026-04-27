---
title: Amazon Firecracker Virtio PCI Out-of-Bounds Write Vulnerability (CVE-2026-5747)
slug: 2026-04-firecracker-oob-write
description: An out-of-bounds write vulnerability in Amazon Firecracker's virtio PCI transport (CVE-2026-5747) allows a local guest user with root privileges to potentially crash the VMM process or execute arbitrary code on the host.
date: "2026-04-08T00:16:05Z"
severities:
  - high
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

CVE-2026-5747 is an out-of-bounds write vulnerability affecting the virtio PCI transport implementation in Amazon Firecracker versions 1.13.0 through 1.14.3 and 1.15.0, specifically on x86_64 and aarch64 architectures. This vulnerability could be exploited by a malicious local guest user who has gained root privileges within the guest operating system. Successful exploitation could lead to a denial-of-service condition by crashing the Firecracker Virtual Machine Monitor (VMM) process. In…
