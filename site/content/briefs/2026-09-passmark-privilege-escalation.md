---
title: Local Privilege Escalation in PassMark Software Drivers
slug: 2026-09-passmark-privilege-escalation
description: PassMark PerformanceTest, BurnInTest, and OSForensics contain a vulnerability in the DirectIo64.sys driver that allows local users to clear arbitrary physical memory bits, enabling privilege escalation.
date: "2026-09-04T19:27:10Z"
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
  - windows
  - kernel-vulnerability
vendors:
  - PassMark Software
products:
  - PerformanceTest (< 11.1 build 1012)
  - BurnInTest (< 11.1 build 1000)
  - OSForensics (< 11.1 build 1016)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker can leverage this flaw to clear arbitrary bits in physical memory... resulting in local privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-80113
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80113
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade PerformanceTest to 11.1 or later
      owner: IT Operations
      due: 72h
      evidence: PassMark security disclosure.
  mitigation_plan:
    - priority: immediate
      action: Upgrade PassMark PerformanceTest to 11.1 build 1012+, BurnInTest to 11.1 build 1000+, and OSForensics to 11.1 build 1016+.
      owner: IT Operations
      addresses: CVE-2026-80113
      evidence: Source provided build requirements.
---

PassMark Software has disclosed a privilege escalation vulnerability affecting PerformanceTest (before 11.1 build 1012), BurnInTest (before 11.1 build 1000), and OSForensics (before 11.1 build 1016). The flaw resides in the DirectIo64.sys driver, which exposes an IOCTL handler that fails to validate the physical address parameter. A local attacker can gain a device handle to the driver and invoke MmMapIoSpace with a user-supplied 64-bit physical address and bit index. By clearing bits in critical kernel code pages or page table entries, an attacker can modify kernel-level structures to achieve local privilege escalation. This vulnerability represents a significant risk for systems where these forensic and testing tools are installed, as they often run with high privileges.

## Attack Chain

1. Attacker gains low-privileged local access to a Windows system where affected PassMark software is installed.
2. Attacker enumerates the device driver DirectIo64.sys to obtain a handle for communication.
3. Attacker identifies the specific IOCTL handler within the driver that facilitates physical memory interaction.
4. Attacker constructs a malicious payload containing an arbitrary 64-bit physical address and a targeted bit index.
5. Attacker sends the IOCTL request to the driver to invoke the vulnerable MmMapIoSpace function.
6. The driver processes the request without validating the address range, clearing the specified bits in kernel memory.
7. Attacker triggers a modification to a page table entry or kernel code page to overwrite security-sensitive data structures.
8. Attacker gains elevated (SYSTEM) privileges on the local machine.

## Impact

Successful exploitation allows local attackers to bypass Windows security controls, resulting in full system compromise. This impact is critical in enterprise environments where forensic or testing tools are deployed on sensitive endpoints.

## Recommendation

1. Upgrade PassMark PerformanceTest to build 1012 or later, BurnInTest to build 1000 or later, and OSForensics to build 1016 or later immediately.
2. Audit for the existence of DirectIo64.sys across the enterprise to identify vulnerable hosts.
3. Restrict access to diagnostic and forensic tools to authorized administrators only.
