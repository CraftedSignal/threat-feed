---
title: Improper Access Control in PassMark DirectIo64.sys Kernel Driver
slug: 2026-09-passmark-privilege-escalation
description: An improper access control vulnerability (CVE-2026-80112) in the DirectIo64.sys kernel driver allows unprivileged local users to perform privileged hardware operations via direct IOCTL communication.
date: "2026-09-04T19:27:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:passmark:performancetest:*:*:*:*:*:*:*:*
  - cpe:2.3:a:passmark:burnintest:*:*:*:*:*:*:*:*
  - cpe:2.3:a:passmark:osforensics:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - kernel-driver
  - windows
  - cve-2026-80112
vendors:
  - PassMark
products:
  - PerformanceTest (< 11.1 build 1012)
  - BurnInTest (< 11.1 build 1000)
  - OSForensics (< 11.1 build 1016)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The DirectIo64.sys kernel driver allows unprivileged local users to perform privileged hardware operations by opening a handle to the device object created without a security descriptor.
    confidence_band: high
cves:
  - id: CVE-2026-80112
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80112
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade PerformanceTest to 11.1 build 1012, BurnInTest to 11.1 build 1000, and OSForensics to 11.1 build 1016
      owner: IT Operations
      addresses: CVE-2026-80112
      evidence: NVD vulnerability details regarding DirectIo64.sys
---

PassMark Software has addressed a security vulnerability identified as CVE-2026-80112 affecting multiple applications, including PerformanceTest, BurnInTest, and OSForensics. The vulnerability stems from an improper access control implementation within the DirectIo64.sys kernel driver. Specifically, the driver creates a device object without an explicit security descriptor, resulting in a permissive default Windows Access Control List (ACL). This flaw allows unprivileged local users to open a handle to the device object and issue IOCTL requests, effectively bypassing standard privilege and integrity level restrictions to execute privileged hardware operations. Attackers could leverage this access to perform unauthorized system-level actions. Defenders should prioritize patching the affected software versions as listed below to mitigate local exploitation risks.

## Impact

Successful exploitation allows a local, unprivileged user to interact with the kernel-mode driver, enabling the execution of privileged hardware operations. This represents a significant escalation of privilege vulnerability that could be used by malware already resident on a system to gain deeper access to the operating system's hardware layer.

## Recommendation

- Upgrade PassMark PerformanceTest to build 1012 or later.
- Upgrade PassMark BurnInTest to build 1000 or later.
- Upgrade PassMark OSForensics to build 1016 or later.
- Review systems for the presence of the vulnerable DirectIo64.sys driver to identify legacy installations pending remediation.
