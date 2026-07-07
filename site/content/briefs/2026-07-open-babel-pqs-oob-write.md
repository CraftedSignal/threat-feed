---
title: Open Babel PQS coord_file parser suffers from out-of-bounds write vulnerability (CVE-2022-43467)
slug: 2026-07-open-babel-pqs-oob-write
description: A high-severity memory-safety vulnerability (CVE-2022-43467) in Open Babel's PQS `coord_file` parser allows an attacker to achieve an out-of-bounds write by tricking a victim into opening a specially crafted PQS file, potentially leading to arbitrary code execution or denial of service in systems processing untrusted chemistry file formats.
date: "2026-07-03T12:53:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:3.1.1:*:*:*:*:*:*:*
tags:
  - open-babel
  - vulnerability
  - memory-corruption
  - cve
  - library
vendors:
  - Open Babel
products:
  - 'Open Babel (vulnerable: < 3.2.0)'
  - 'pip/openbabel (vulnerable: < 3.2.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious PQS file with the `obabel` tool, the `OBConversion` API, or any of the language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Application Compromise: Arbitrary Code Execution'
    evidence: This memory corruption can lead to application crash (Denial of Service) or, with further exploitation, arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2022-43467
    cvss: 9.8
    epss: 0.00843
references:
  - https://github.com/advisories/GHSA-f29h-2h58-48r7
  - https://github.com/openbabel/openbabel/commit/2a7d2cda
---

A high-severity memory-safety vulnerability, identified as CVE-2022-43467, has been discovered in Open Babel's PQS `coord_file` parser. This flaw affects all versions up to and including 3.1.1 of the Open Babel library and CLI tool, which is critical for processing various chemistry file formats. Exploitation occurs when a victim processes a specially crafted PQS file, leading to an out-of-bounds write within the `coord_file` parsing path. This vulnerability was reported by Cisco TALOS and subsequently patched in version 3.2.0, released on 2026-05-26. Given Open Babel's widespread use across Linux distributions and in services that handle untrusted input, this flaw poses a significant risk of arbitrary code execution or denial of service.

## Attack Chain

1. An attacker crafts a specially designed PQS file containing a malformed `coord_file` specifier that targets the vulnerability.
2. The attacker delivers this malicious PQS file to a target system or user, often via email, download, or integration into a workflow.
3. A user or automated service on the victim system opens and processes the malicious PQS file using an affected Open Babel component (e.g., `obabel` CLI tool, `OBConversion` API, or language bindings).
4. During the parsing process of the PQS `coord_file` path, the malformed specifier triggers an out-of-bounds write operation.
5. This memory corruption overwrites adjacent memory regions, leading to unpredictable program behavior, including crashes.
6. Successful exploitation can result in application crashes (Denial of Service) or, with further exploitation, arbitrary code execution on the compromised system.

## Impact

The vulnerability affects any system or service utilizing Open Babel versions up to 3.1.1 to process PQS files, particularly those that handle untrusted or external input. Open Babel is widely deployed as a C++ library and command-line interface, integrated into Linux distributions and various scientific applications. Successful exploitation of CVE-2022-43467 can lead to service disruption through denial of service (application crashes) or, more severely, arbitrary code execution, allowing attackers to gain control over affected systems. The full scope of potential victims is broad due to the library's foundational role in chemistry informatics.

## Recommendation

*   Immediately update all Open Babel installations to version 3.2.0 or later to patch CVE-2022-43467.
*   For Python environments, ensure `pip/openbabel` is updated to a version greater than or equal to 3.2.0.
*   Implement strict input validation for all PQS files processed by Open Babel components, especially those originating from untrusted sources, to mitigate the risk of malformed file attacks.
