---
title: Heap-Based Buffer Overflow in RPM Package Manager (CVE-2026-95520)
slug: 2026-09-rpm-heap-overflow
description: A heap-based buffer overflow in the RPM Package Manager allows for out-of-bounds writes and potential code execution when processing maliciously crafted RPM files containing specific symlink entries.
date: "2026-09-29T12:27:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rpm_package_manager:rpm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - rpm
  - linux
vendors:
  - RPM Package Manager
products:
  - rpm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This is reachable via rpm2cpio, rpm2archive, and rpm -qlvp on an untrusted package.
    confidence_band: high
cves:
  - id: CVE-2026-95520
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95520
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Identify systems running RPM utilities on untrusted packages and restrict access to these tools where possible.
      owner: Security Operations
      due: 48h
  hunt_leads:
    - lead: Monitor execution of rpm, rpm2cpio, or rpm2archive on files downloaded from external repositories.
      technique_id: T1203
      data_needed:
        - Process creation logs with command line arguments
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Upgrade rpm to the version containing the patch for CVE-2026-95520.
      owner: IT Operations
      addresses: CVE-2026-95520
---

CVE-2026-95520 is a critical heap-based buffer overflow vulnerability identified in the RPM Package Manager. The vulnerability resides in the iterReadArchiveNext() function, which is responsible for processing archive entries within an RPM package. An attacker can exploit this by providing a specially crafted RPM file containing a symlink entry where the RPMTAG_LONGFILESIZES value is set to 0xFFFFFFFFFFFFFFFF. This specific value triggers an integer overflow, causing the allocation of an undersized buffer (one byte). Subsequent processing of the cpio filesize field allows the attacker to write data beyond the boundary of this buffer. This vulnerability is reachable through common RPM inspection and extraction utilities, including rpm2cpio, rpm2archive, and the rpm -qlvp command. Successfully exploiting this flaw could lead to arbitrary code execution on systems that process untrusted RPM packages.

## Impact

Successful exploitation of CVE-2026-95520 allows an attacker to execute arbitrary code with the privileges of the user running the RPM inspection or extraction tools. This poses a significant risk to systems that routinely process third-party or untrusted RPM packages, such as build servers, repository mirrors, or security analysis environments. The ability to trigger this via basic tools like rpm -qlvp significantly increases the attack surface for local users and automated systems alike.

## Recommendation

Prioritize the identification of systems that utilize the RPM Package Manager tools to inspect or extract files from external sources. Monitor environments for the execution of rpm, rpm2cpio, and rpm2archive against files originating from untrusted locations. Patch the RPM Package Manager as soon as an updated version is released by the distribution maintainers to address this heap overflow vulnerability.
