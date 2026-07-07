---
title: Open Babel Out-of-Bounds Write in MSI Parser (CVE-2022-46295)
slug: 2026-07-open-babel-oob-write
description: An out-of-bounds write vulnerability (CVE-2022-46295) in Open Babel's MSI parser allows remote attackers to cause memory corruption, denial of service, or potentially arbitrary code execution when a victim opens a specially crafted MSI file using the `obabel` tool or any application linked to the `OBConversion` API.
date: "2026-07-03T12:46:55Z"
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
  - library
  - cpp
  - ghsa
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious MSI file with the `obabel` tool, the `OBConversion` API, or any of the language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
    confidence_band: high
cves:
  - id: CVE-2022-46295
    cvss: 9.8
    epss: 0.00816
references:
  - https://github.com/advisories/GHSA-f8h2-c479-vqxf
  - https://github.com/openbabel/openbabel/commit/40e85213
---

A significant memory-safety vulnerability, tracked as CVE-2022-46295, has been identified in Open Babel, a widely used C++ library and command-line interface for interconverting chemical file formats. The flaw specifically resides within the MSI parser, where a fixed-size `translationVectors[]` array is susceptible to an out-of-bounds write. Attackers can exploit this by crafting a malformed MSI file that, when processed by vulnerable versions of Open Babel (all releases up to and including 3.1.1), causes the parser to write more vectors than the array's capacity. This memory corruption can lead to denial of service or, in more advanced scenarios, arbitrary code execution. Given Open Babel's inclusion in various Linux distributions and its integration into services that may process untrusted input, the potential impact is broad, affecting scientific, pharmaceutical, and chemical sectors. The vulnerability was patched in Open Babel version 3.2.0, released in May 2026, following a report by Cisco TALOS.

## Attack Chain

1.  **Attacker Crafts Malicious MSI File**: An attacker creates a specially malformed MSI file designed to push more cell translation vectors than the `translationVectors[]` array can hold within Open Babel's MSI parser.
2.  **Delivery of Malicious File**: The crafted MSI file is delivered to a target system, often via email, malicious download, or an untrusted file share.
3.  **Victim Processes Malicious File**: The victim opens the malicious MSI file using the `obabel` command-line tool, an application that links the `OBConversion` API, or any of Open Babel's language bindings (e.g., Python, Ruby, Java, R, Perl, C#, PHP).
4.  **Vulnerable Parsing Initiated**: Open Babel's MSI parser initiates processing of the malformed input file to extract chemical structure data.
5.  **Out-of-Bounds Write Occurs**: During the parsing of the crafted MSI file, the vulnerable logic attempts to write an excessive number of cell translation vectors into the fixed-size `translationVectors[]` array, resulting in an out-of-bounds write past the array's allocated memory region.
6.  **Memory Corruption**: The out-of-bounds write corrupts adjacent memory, leading to unpredictable program behavior.
7.  **Denial of Service or Arbitrary Code Execution**: This memory corruption can cause the application to crash, resulting in a denial of service, or potentially be leveraged by an attacker to achieve arbitrary code execution on the compromised system.

## Impact

This vulnerability, CVE-2022-46295, impacts organizations utilizing Open Babel for chemical file format processing, particularly those handling untrusted MSI files. Due to Open Babel's common inclusion in Linux distributions and its embedding within various services, a wide array of sectors, from academic research to pharmaceutical and chemical industries, could be affected. Successful exploitation results in memory corruption, leading to application crashes and denial of service, or potentially allowing an attacker to achieve arbitrary code execution, compromising data integrity, confidentiality, or system control.

## Recommendation

*   Upgrade all installations of Open Babel to version 3.2.0 or newer to remediate CVE-2022-46295.
*   Implement strict input validation and sandboxing for applications processing untrusted MSI files using Open Babel to limit the potential impact of memory corruption vulnerabilities like CVE-2022-46295.
*   Monitor systems for crashes of `obabel` processes or applications linked against `OBConversion` library functions, which could indicate attempts at exploiting vulnerabilities like CVE-2022-46295.
