---
title: Local Privilege Escalation in BioStar VALKYRIE AURORA Driver
slug: 2026-09-biostar-valkyrie-aurora-rce
description: CVE-2026-94129 is a local privilege escalation vulnerability in the BioStar VALKYRIE AURORA driver BS_RVSIO64.sys allowing arbitrary memory writes via an IOCTL handler.
date: "2026-09-21T02:25:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:biostar:valkyrie_aurora:2.10.2411.0800:*:*:*:*:*:*:*
tags:
  - windows
  - privilege-escalation
  - kernel
vendors:
  - BioStar
products:
  - VALKYRIE AURORA (2.10.2411.0800)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The manipulation of the argument PhysicalAddress results in write-what-where condition.
    confidence_band: high
cves:
  - id: CVE-2026-94129
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94129
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory systems running BioStar VALKYRIE AURORA 2.10.2411.0800
      owner: IT Operations
      due: 24h
      evidence: Source confirms version 2.10.2411.0800 is vulnerable.
  mitigation_plan:
    - priority: medium_term
      action: Restrict non-admin user access to the BS_RVSIO64.sys driver interface
      owner: IT Operations
      addresses: CVE-2026-94129
      evidence: Vulnerability requires local access to trigger.
---

CVE-2026-94129 describes a high-severity security vulnerability in the BioStar VALKYRIE AURORA software version 2.10.2411.0800. The flaw resides within the driver file BS_RVSIO64.sys, specifically impacting the IOCTL handler function sub_1105C. An attacker with local access to the system can manipulate the PhysicalAddress argument, resulting in a write-what-where vulnerability. This condition allows an adversary to perform arbitrary memory writes, potentially leading to local privilege escalation or system compromise. Publicly available exploit code exists for this vulnerability, and the vendor has not responded to disclosure attempts. Because the attack requires local access, this represents a significant risk for systems where untrusted users or applications may interact with the driver interface.

## Impact

Successful exploitation allows a local user to execute arbitrary code with elevated privileges, potentially leading to a full system compromise. The vulnerability affects users of the BioStar VALKYRIE AURORA software version 2.10.2411.0800 on Windows operating systems. If exploited, an attacker could bypass OS security controls to install persistent backdoors, access sensitive data, or disable security software.

## Recommendation

* Monitor system logs for unauthorized access to device drivers or attempts to interact with the BS_RVSIO64.sys interface.
* Audit systems for the presence of BioStar VALKYRIE AURORA version 2.10.2411.0800 and consider restricting access to the executable or driver files until a vendor security update is available.
* Implement endpoint security controls to restrict execution of untrusted binaries that might attempt to interact with IOCTLs of kernel-mode drivers.
