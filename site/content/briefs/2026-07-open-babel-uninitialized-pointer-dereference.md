---
title: Open Babel PQS Parser Uninitialized Pointer Dereference (CVE-2022-46280)
slug: 2026-07-open-babel-uninitialized-pointer-dereference
description: A memory-safety vulnerability, CVE-2022-46280, in Open Babel's PQS parser (versions prior to 3.2.0) allows an uninitialized pointer dereference when processing a specially crafted input file, potentially leading to application crashes and denial of service if a victim opens a malicious PQS file.
date: "2026-07-03T12:50:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - library
  - linux
  - DoS
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
affected_os:
  - Linux
cves:
  - id: CVE-2022-46280
    cvss: 9.8
    epss: 0.00843
references:
  - https://github.com/advisories/GHSA-8qxc-57hf-hc9j
  - https://github.com/openbabel/openbabel/commit/2a7d2cda
  - CVE-2022-46280
---

A significant memory-safety vulnerability, tracked as CVE-2022-46280, has been identified in the Open Babel library, specifically within its PQS parser. This flaw affects all versions up to and including 3.1.1. The vulnerability stems from improper handling of `pFormat` during PQS file parsing, where a malformed input file can cause the parser to dereference an uninitialized pointer. This can lead to application instability, crashes, and potentially denial of service when untrusted PQS files are processed. Open Babel is a widely used C++ chemistry library and command-line tool, often embedded in other services or shipped with Linux distributions, making its exploitation a concern for systems that process untrusted chemical file formats. The vulnerability was responsibly disclosed by Cisco TALOS.

## Attack Chain

1.  An attacker crafts a malicious PQS (Protein Query System) input file specifically designed to exploit the uninitialized pointer dereference vulnerability.
2.  The attacker delivers this malicious PQS file to a victim system through various means, such as email attachments, malicious websites, or shared network drives.
3.  The victim user or an automated service is induced to open or process the malicious PQS file using the `obabel` command-line tool, the `OBConversion` API, or any language binding (e.g., Python, Ruby, Java, R, Perl, C#, PHP) that utilizes the vulnerable Open Babel library.
4.  During the parsing of the malformed PQS file, the Open Babel library attempts to access a `pFormat` pointer that has not been correctly initialized.
5.  This uninitialized pointer dereference triggers a memory access violation or segmentation fault within the application using Open Babel.
6.  The application crashes, leading to a denial of service (DoS) for the affected process or system, depending on how Open Babel is integrated.

## Impact

The primary impact of CVE-2022-46280 is a denial of service (DoS) for applications or systems that utilize the vulnerable Open Babel library to parse untrusted PQS files. If a malicious PQS file is processed, the application will crash, rendering it temporarily or permanently unavailable until manually restarted or if the system's fault tolerance mechanisms kick in. Given Open Babel's widespread use in scientific computing, chemistry, and various Linux distributions, this vulnerability could affect a broad range of services or end-user workstations that handle chemical data. While not directly leading to arbitrary code execution, repeated crashes could disrupt research workflows, automated processing pipelines, or critical scientific infrastructure.

## Recommendation

*   **Patch CVE-2022-46280 immediately** by upgrading Open Babel to version 3.2.0 or newer. Refer to https://github.com/advisories/GHSA-8qxc-57hf-hc9j for details.
*   Implement strict input validation and sanitization for all PQS files processed by applications utilizing Open Babel, particularly those obtained from untrusted sources.
*   Segregate critical services that process PQS files into isolated environments to limit the blast radius of potential crashes.
*   Ensure that all instances of the `obabel` tool and any applications leveraging the Open Babel library are updated to the patched version.
