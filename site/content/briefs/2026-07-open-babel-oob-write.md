---
title: Open Babel Out-of-Bounds Write Vulnerability (CVE-2022-46290)
slug: 2026-07-open-babel-oob-write
description: A memory-safety vulnerability (CVE-2022-46290) in the ORCA nAtoms parser of Open Babel allows an out-of-bounds write when processing a specially crafted input file, potentially leading to denial of service or arbitrary code execution.
date: "2026-07-03T12:48:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - memory-safety
  - vulnerability
  - out-of-bounds-write
  - open-babel
  - cve
vendors:
  - Open Babel
products:
  - Open Babel < 3.2.0
cves:
  - id: CVE-2022-46290
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-5rff-8f7c-8jmw
  - https://github.com/openbabel/openbabel/commit/b239d06e
---

A significant memory-safety vulnerability, identified as CVE-2022-46290, exists within the ORCA nAtoms parser of the Open Babel chemistry library. This flaw is a second variant of an existing out-of-bounds write issue, where a different malformed input path in ORCA files can cause data to be written beyond the allocated buffer. The vulnerability affects all versions of Open Babel up to and including 3.1.1. It was patched in version 3.2.0, released on 2026-05-26. Exploitation requires a victim to open a malicious ORCA file using the `obabel` command-line tool, the `OBConversion` API, or any of its language bindings (Python, Ruby, Java, R, Perl, C#, PHP). Organizations leveraging Open Babel to process untrusted or external chemistry file formats are at risk.

## Attack Chain

1.  An attacker crafts a malicious ORCA (Organizing Reaction and Coordinate Automation) input file containing specially malformed `nAtoms` data.
2.  The attacker delivers this crafted ORCA file to a target system, often by inducing a user or automated process to handle it (e.g., via email, web download, or file sharing).
3.  A victim user or an automated service on the target system attempts to open or process the malicious ORCA file using Open Babel's `obabel` CLI tool, its `OBConversion` API, or one of its various language bindings.
4.  Open Babel's ORCA nAtoms parser, specifically the vulnerable code path, encounters the malformed input while attempting to parse the file.
5.  Due to the vulnerability (CVE-2022-46290), the parser performs an out-of-bounds write operation, writing data beyond the boundaries of an intended memory buffer.
6.  This memory corruption can lead to application crashes (denial of service) or, in more sophisticated scenarios, could be leveraged by an attacker to achieve arbitrary code execution.

## Impact

Successful exploitation of CVE-2022-46290 can result in memory corruption within the Open Babel application or its host process. The immediate consequence is typically a denial of service due to an application crash. However, depending on the specific memory layout and attacker's control over the written data, this out-of-bounds write could potentially lead to arbitrary code execution, allowing an attacker to run malicious code on the affected system. Any organization or user processing untrusted ORCA chemistry files with vulnerable versions of Open Babel is at risk, particularly those deployed in automated pipelines or services exposed to external input. While no specific victim counts are provided, Open Babel is widely used across scientific and industrial sectors.

## Recommendation

*   **Patch CVE-2022-46290**: Immediately update all instances of Open Babel to version 3.2.0 or newer to mitigate the out-of-bounds write vulnerability.
*   **Input Validation**: Implement strict validation and sanitization for all ORCA input files processed by Open Babel, especially those sourced from untrusted origins.
*   **Isolation**: Isolate systems and applications that process external or untrusted chemistry file formats in sandboxed environments to limit potential impact of exploitation.
