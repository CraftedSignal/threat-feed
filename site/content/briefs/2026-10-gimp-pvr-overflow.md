---
title: Integer Overflow Vulnerability in GIMP file-pvr Plug-in
slug: 2026-10-gimp-pvr-overflow
description: An integer overflow vulnerability in the GIMP file-pvr plug-in allows heap-based buffer overflow via malicious .pvr files, potentially leading to arbitrary code execution or application crashes.
date: "2026-10-16T22:44:41Z"
lastmod: "2026-10-20T00:30:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gimp:gimp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - gimp
  - memory-corruption
  - cve-2026-112258
vendors:
  - GIMP
products:
  - GIMP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: By tricking a user into opening or previewing a specially crafted PowerVR (.pvr) file, an attacker can trigger a heap-based buffer overflow, potentially leading to arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: An attacker could exploit this by tricking a user into opening a malicious XCF file.
    confidence_band: high
cves:
  - id: CVE-2026-62439
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62439
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112260
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112257
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112258
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade GIMP to the latest version once the vendor releases a patch for CVE-2026-62439
      owner: IT Operations
      addresses: CVE-2026-62439
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-19T22:23:36Z"
    level: L1
    summary: added coverage for GIMP
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112260
  - at: "2026-10-20T00:30:33Z"
    level: L2
    summary: added coverage for GIMP
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112257
  - at: "2026-10-20T00:30:38Z"
    level: L2
    summary: added coverage for GIMP
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112258
---

A security vulnerability (CVE-2026-62439) has been identified in the GIMP image manipulation software. The flaw exists within the file-pvr plug-in, which is responsible for parsing PowerVR (.pvr) image files. An integer overflow occurs during the calculation of memory buffer sizes based on the image dimensions provided in the file header. An attacker can exploit this by enticing a victim to open or preview a specially crafted .pvr image file. Successful exploitation leads to a heap-based buffer overflow, which can result in an application crash (Denial of Service) or arbitrary code execution within the context of the user running GIMP. This vulnerability affects GIMP across all supported platforms, including Windows, Linux, and macOS. Users are advised to upgrade to a patched version once available and avoid opening untrusted or unknown .pvr files.

## Impact

Successful exploitation of CVE-2026-62439 allows an unauthenticated attacker to achieve code execution or perform a denial of service attack against the GIMP application. This presents a high risk to users who frequently work with external or untrusted graphics files. Organizations should identify systems where GIMP is installed and monitor for the opening of .pvr files from untrusted sources until patches are applied.

## Recommendation

* Monitor endpoint file access logs for GIMP (gimp-2.x.exe or gimp-console) opening files with the .pvr extension.
* Disable or remove the file-pvr plug-in if PVR image support is not required for business operations.
* Apply vendor security updates for GIMP as soon as they are made available to address CVE-2026-62439.
