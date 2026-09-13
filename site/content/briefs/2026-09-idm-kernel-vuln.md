---
title: Improper Access Control in Tonec Internet Download Manager Kernel Driver
slug: 2026-09-idm-kernel-vuln
description: CVE-2026-90493 is a local privilege escalation vulnerability in the Tonec Internet Download Manager idmwfp.sys kernel driver, allowing attackers with local access to manipulate improper access controls.
date: "2026-09-13T03:24:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tonec:internet_download_manager:*:*:*:*:*:windows:*:*
tags:
  - windows
  - privilege-escalation
  - kernel-vulnerability
vendors:
  - Tonec
products:
  - Internet Download Manager (<= 6.42 Build 63)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation results in improper access controls.
    confidence_band: high
cves:
  - id: CVE-2026-90493
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90493
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit environment for systems running Internet Download Manager 6.42 Build 63 or earlier
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90493 vulnerability scope
  mitigation_plan:
    - priority: immediate
      action: Remove or disable Internet Download Manager on high-risk systems until a vendor patch is released
      owner: IT Operations
      addresses: CVE-2026-90493
      evidence: Vendor has not provided a response or patch
---

CVE-2026-90493 affects Tonec Internet Download Manager versions 6.42 Build 63 and earlier on Windows. The vulnerability exists within the idmwfp.sys kernel driver, which handles filter operations for the application. A local attacker can interact with this driver to perform unauthorized operations due to improper access control mechanisms. Because the driver operates at the kernel level, this vulnerability is a significant risk for privilege escalation and security boundary bypass. Exploitation requires the attacker to already have local access to the target system. Public exploit material is available, increasing the risk of abuse. The vendor has not provided a response or a patch to address the issue at the time of disclosure.

## Impact

Successful exploitation of CVE-2026-90493 allows a local user to escalate privileges or perform unauthorized actions at the kernel level. This compromises the integrity of the host operating system, potentially enabling an attacker to disable security software, bypass endpoint protections, or maintain persistence with system-level access. Organizations utilizing affected versions of Internet Download Manager on Windows systems are at elevated risk if local users or low-privileged processes are compromised.

## Recommendation

Prioritize restricting local access to the affected Windows systems to mitigate the threat of local privilege escalation. Given that the vendor has not provided a security update, detection and monitoring should focus on identifying unauthorized attempts to interact with the idmwfp.sys driver.

* Monitor system logs for unexpected loading of the idmwfp.sys driver or unusual IOCTL (Input/Output Control) calls directed at this driver if telemetry is available.
* Audit systems running Internet Download Manager to identify instances of the vulnerable version 6.42 Build 63 or earlier.
* If the software is not mission-critical, consider uninstalling or disabling Internet Download Manager until a vendor-supplied patch is available.
