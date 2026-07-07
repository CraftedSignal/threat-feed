---
title: Open Babel has out-of-bounds write in CSR PadString (title field)
slug: 2026-07-open-babel-oob-write
description: A memory-safety vulnerability (CVE-2022-41793) exists in Open Babel's CSR parser, specifically in the `PadString` helper used for the title field, allowing an out-of-bounds write when a crafted input file with an overly long title is processed, potentially leading to denial of service or arbitrary code execution.
date: "2026-07-03T12:54:46Z"
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
  - cve
  - library
  - linux
  - open-babel
vendors:
  - Open Babel
products:
  - Open Babel < 3.2.0
  - pip/openbabel < 3.2.0
cves:
  - id: CVE-2022-41793
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-p594-7xw4-g76p
  - https://github.com/openbabel/openbabel/commit/528c142f
---

A memory-safety vulnerability, CVE-2022-41793, has been identified in the Open Babel C++ library and command-line interface, specifically affecting its CSR (Crystallographic Structure Report) file parser. The flaw resides in the `PadString` helper function, which is responsible for handling the title field within CSR files. When Open Babel attempts to process a CSR file containing a title longer than its fixed destination buffer, the `PadString` function performs an out-of-bounds write, overwriting adjacent memory. This vulnerability affects all Open Babel releases up to and including version 3.1.1, with a patch released in version 3.2.0 on May 26, 2026. This is particularly concerning for environments that parse untrusted input files, as Open Babel is widely used in scientific computing, shipped by Linux distributions, and integrated into various services via its API and language bindings. The vulnerability was reported by Cisco TALOS.

## Impact

The out-of-bounds write vulnerability in Open Babel's CSR parser can lead to various severe consequences, including denial of service (application crash) due to memory corruption, or potentially arbitrary code execution if an attacker can precisely control the overwritten memory regions. Open Babel is a critical component in chemistry-related software stacks, frequently used for converting, analyzing, and storing chemical data. Organizations that embed Open Babel in services or use the `obabel` tool or its language bindings (Python, Ruby, Java, R, Perl, C#, PHP) to parse untrusted CSR files are at risk. Exploitation requires a victim to open a specially crafted malicious CSR file. Given its widespread use, this could impact numerous scientific, academic, and industrial sectors handling chemical data.

## Recommendation

Prioritized, concrete actions for detection engineering teams.
*   Patch CVE-2022-41793 by upgrading Open Babel to version 3.2.0 or later immediately.
