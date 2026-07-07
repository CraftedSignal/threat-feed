---
title: Open Babel Out-of-Bounds Write Vulnerability (CVE-2022-46292)
slug: 2026-07-open-babel-oob-write
description: A high-severity memory-safety vulnerability (CVE-2022-46292) in Open Babel's MOPAC output parser allows an out-of-bounds write into the `translationVectors[]` array when processing a crafted MOPAC output file, potentially leading to denial of service or arbitrary code execution.
date: "2026-07-06T16:44:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - memory-corruption
  - vulnerability
  - open-babel
  - client-side
vendors:
  - Open Babel
products:
  - Open Babel < 3.2.0
cves:
  - id: CVE-2022-46292
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-55f6-pf8r-c2f4
  - https://github.com/openbabel/openbabel/commit/40e85213
---

A high-severity memory-safety vulnerability, identified as CVE-2022-46292, has been discovered in Open Babel, a widely used C++ library and command-line tool for converting and manipulating chemistry file formats. Reported by Cisco TALOS, this flaw specifically affects the MOPAC output parser, enabling an out-of-bounds write into the `translationVectors[]` array. The vulnerability is triggered when Open Babel attempts to process a specially crafted MOPAC output file containing an overly large "UNIT CELL TRANSLATION" block. This can occur when a victim uses the `obabel` tool, the `OBConversion` API, or any language binding to open a malicious MOPAC file. All Open Babel versions up to and including 3.1.1 are affected, with a patch released in version 3.2.0. Successful exploitation could lead to memory corruption, application crashes, or potentially arbitrary code execution.

## Attack Chain

1.  An attacker crafts a malicious MOPAC output file containing an oversized "UNIT CELL TRANSLATION" block designed to exceed the fixed-size `translationVectors[]` array limit.
2.  The attacker distributes the malicious MOPAC file to a target victim through social engineering tactics, such as email attachments or links to compromised websites.
3.  The victim is lured into opening or processing the malicious MOPAC file using the `obabel` command-line tool, an application leveraging Open Babel's `OBConversion` API, or one of its language bindings.
4.  Open Babel's MOPAC output parser initiates the reading of the "UNIT CELL TRANSLATION" block from the attacker's crafted file.
5.  As the parser processes the malformed block, it attempts to write more translation vectors into the `translationVectors[]` array than its allocated memory can hold.
6.  This action results in an out-of-bounds write operation, corrupting memory located immediately after the `translationVectors[]` array.
7.  The memory corruption leads to a denial of service (application crash), information disclosure, or, in some scenarios, arbitrary code execution.
8.  If arbitrary code execution is achieved, the attacker can compromise the affected system, potentially leading to data exfiltration or further lateral movement.

## Impact

The vulnerability affects Open Babel, a core component in various scientific computing environments, including those embedded in services and shipped by Linux distributions. If successfully exploited, CVE-2022-46292 can cause the `obabel` tool or any application using its libraries to crash, leading to a denial of service. More critically, an out-of-bounds write can be leveraged for arbitrary code execution, granting attackers control over the victim's system, allowing for data exfiltration, system compromise, or the installation of additional malware. The broad usage of Open Babel means that a successful attack could impact a wide range of academic, research, and industrial sectors that rely on chemical data processing.

## Recommendation

*   Patch CVE-2022-46292 immediately by updating all Open Babel installations to version 3.2.0 or newer.
*   Implement strict input validation for MOPAC files processed by Open Babel, especially for files originating from untrusted sources.
*   Educate users on the risks associated with opening or processing untrusted or unverified MOPAC output files.
