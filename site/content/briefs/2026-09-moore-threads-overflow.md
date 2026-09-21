---
title: Heap-based Buffer Overflow in Moore Threads MTT S80 Driver
slug: 2026-09-moore-threads-overflow
description: A heap-based buffer overflow in the Moore Threads MTT S80 driver (mtdispkm64.sys) allows a local attacker to potentially achieve privilege escalation or system instability via a crafted IOCTL request.
date: "2026-09-21T22:30:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:moorethreads:mtt_s80_driver_package:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - kernel-vulnerability
vendors:
  - Moore Threads
products:
  - MTT S80 Driver Package (<= 340.150)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation leads to heap-based buffer overflow... An attack has to be approached locally.
    confidence_band: high
cves:
  - id: CVE-2026-94424
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94424
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict local interactive logon rights for untrusted accounts on systems using MTT S80 hardware.
      owner: IT Operations
      due: 48h
      evidence: Exploit requires local access.
  mitigation_plan:
    - priority: medium_term
      action: Remove or disable Moore Threads MTT S80 driver on critical systems.
      owner: IT Operations
      addresses: CVE-2026-94424
      evidence: Unpatched vulnerability in kernel driver.
---

A heap-based buffer overflow vulnerability, identified as CVE-2026-94424, exists in the Moore Threads MTT S80 Driver Package up to version 340.150. The vulnerability resides within the IOCTL handler function, specifically sub_140001000, located in the kernel-mode driver file mtdispkm64.sys. An attacker possessing local access to a system running the affected driver can trigger the overflow by sending a specially crafted I/O control request to the driver. This manipulation may lead to unauthorized privilege escalation or kernel-level memory corruption, potentially causing a system crash or arbitrary code execution in a privileged context. The vendor has been unresponsive to disclosure attempts, and as of the report date, no security patches are available to remediate this flaw.

## Impact

Successful exploitation of this vulnerability by a local attacker can lead to full system compromise, as the affected component operates in kernel mode. This poses a significant risk to workstations or servers utilizing the MTT S80 GPU hardware, as it allows unprivileged local users to elevate their privileges to SYSTEM. The current lack of vendor response means systems remain exposed, and defense-in-depth measures are required to mitigate the risk until an update is provided.

## Recommendation

* Monitor for unexpected system crashes or kernel-mode events involving the mtdispkm64.sys module.
* Audit local user accounts to ensure only authorized personnel have interactive logon capabilities on systems equipped with Moore Threads hardware.
* Limit access to raw device handles for the MTT S80 driver, if feasible via restrictive access control lists (ACLs) on the device object.
* Disable or uninstall the Moore Threads MTT S80 driver on high-security systems where the hardware acceleration is not strictly required until the vendor provides a patch.
