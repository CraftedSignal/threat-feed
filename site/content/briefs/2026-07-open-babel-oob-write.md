---
title: Open Babel ORCA Parser Out-of-Bounds Write Vulnerability (CVE-2022-46289)
slug: 2026-07-open-babel-oob-write
description: A memory-safety vulnerability (CVE-2022-46289) in Open Babel's ORCA parser allows an out-of-bounds write when processing a crafted input file, potentially leading to denial of service or arbitrary code execution if a victim opens a malicious ORCA file.
date: "2026-07-03T12:49:41Z"
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
  - cve
  - open-babel
  - client-side
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious ORCA file with the `obabel` tool, the `OBConversion` API, or any of the language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
    confidence_band: high
cves:
  - id: CVE-2022-46289
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-rj4c-r689-cm87
  - https://github.com/openbabel/openbabel/commit/b239d06e
---

Cisco TALOS reported a critical memory-safety vulnerability, identified as CVE-2022-46289, affecting the widely used Open Babel library. This flaw resides within the ORCA file format parser, specifically in the `nAtoms` handling mechanism. An attacker can craft a malicious ORCA input file which, when processed by Open Babel, causes the parser to write data beyond the bounds of its designated memory buffer. This out-of-bounds write can lead to application crashes, denial of service, or potentially arbitrary code execution. The vulnerability impacts all Open Babel versions up to and including 3.1.1. Open Babel is a fundamental toolkit for chemistry file format conversion, often integrated into scientific applications and Linux distributions, making it a significant target if exposed to untrusted input. The issue was addressed in version 3.2.0, released on May 26, 2026.

## Attack Chain

1.  An attacker crafts a specially malformed ORCA chemistry input file designed to trigger the out-of-bounds write vulnerability (CVE-2022-46289) in Open Babel.
2.  The attacker delivers this malicious ORCA file to a victim, potentially via email attachments, malicious downloads, or through shared scientific data repositories.
3.  The victim opens the ORCA file using the `obabel` command-line tool, an application that embeds the `OBConversion` API, or any of Open Babel's language bindings (e.g., Python, Ruby, Java).
4.  The Open Babel ORCA parser attempts to process the malformed `nAtoms` field within the attacker-controlled input file.
5.  During the parsing of the malformed data, the vulnerability causes the parser to perform an out-of-bounds write, corrupting memory outside its allocated buffer.
6.  This memory corruption can lead to a denial of service by crashing the application, or, under specific conditions and with further exploitation techniques, could enable the execution of arbitrary code within the context of the vulnerable process.

## Impact

The successful exploitation of CVE-2022-46289 can result in the compromise of systems and services that utilize Open Babel for processing ORCA files from untrusted sources. The primary impact is application instability and denial of service due to crashes caused by memory corruption. In more advanced exploitation scenarios, an attacker might achieve arbitrary code execution, allowing for further system compromise, data exfiltration, or installation of malware. Open Babel is a widely deployed library in academic, research, and industrial sectors dealing with computational chemistry, meaning a broad range of applications and users could be affected if they process untrusted ORCA files.

## Recommendation

*   Prioritize patching `CVE-2022-46289` by upgrading all instances of Open Babel to version 3.2.0 or later immediately.
*   Implement strict input validation and sanitization for ORCA files processed by Open Babel, especially when sourced from untrusted external entities.
*   Educate users on the risks associated with opening ORCA files from unknown or untrusted sources.
