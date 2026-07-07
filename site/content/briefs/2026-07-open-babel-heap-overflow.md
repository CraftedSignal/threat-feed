---
title: Open Babel Heap Buffer Overflow in ChemKin Parser (CVE-2025-10997)
slug: 2026-07-open-babel-heap-overflow
description: A heap buffer overflow vulnerability (CVE-2025-10997) in Open Babel's ChemKin parser allows an attacker to achieve memory corruption when a victim processes a specially crafted ChemKin file, potentially leading to denial of service or arbitrary code execution.
date: "2026-07-03T13:01:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:*:*:*:*:*:*:*:*
tags:
  - chemistry
  - vulnerability
  - buffer-overflow
  - memory-corruption
  - cve
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
  - pip/openbabel (< 3.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Triggering this vulnerability requires the victim to open a malicious ChemKin file with the `obabel` tool, the `OBConversion` API, or any of the language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
    confidence_band: high
cves:
  - id: CVE-2025-10997
    cvss: 5.3
    epss: 0.00224
references:
  - https://github.com/advisories/GHSA-8wq6-qh76-wpv9
  - https://github.com/openbabel/openbabel/commit/af4a4212
---

A memory-safety vulnerability, identified as CVE-2025-10997, has been discovered in Open Babel, a widely used C++ library and command-line tool for chemistry file format conversion. This flaw, reported via OSS-Fuzz, specifically exists within the `ChemKinFormat::CheckSpecies` function of the ChemKin parser. Attackers can exploit this vulnerability by crafting a malicious ChemKin file that, when processed by a victim using Open Babel components (such as the `obabel` tool, the `OBConversion` API, or its language bindings), causes a heap buffer overflow. This leads to memory corruption, potentially resulting in application crashes (Denial of Service) or, under certain conditions, arbitrary code execution. All Open Babel releases up to and including version 3.1.1 are affected; the vulnerability was patched in version 3.2.0, released on 2026-05-26.

## Attack Chain

1.  Attacker crafts a malicious ChemKin file specifically designed to contain malformed species records, triggering the heap buffer overflow in `ChemKinFormat::CheckSpecies`.
2.  The malicious ChemKin file is delivered to the victim, typically via social engineering (e.g., email attachment), malicious download link, or embedding within a seemingly legitimate data set.
3.  The victim interacts with the malicious file, causing it to be processed by an Open Babel component, such as the `obabel` command-line tool, the `OBConversion` API, or one of its language bindings (Python, Ruby, Java, etc.).
4.  Open Babel's internal parser, specifically within the `ChemKinFormat::CheckSpecies` function, attempts to process the malformed species record from the crafted file.
5.  Due to the malformed data, the `ChemKinFormat::CheckSpecies` function attempts to write data beyond the allocated bounds of a heap-allocated buffer.
6.  This heap buffer overflow corrupts memory, leading to an application crash (Denial of Service) or, under specific conditions, allows for arbitrary code execution on the victim's system.

## Impact

Successful exploitation of CVE-2025-10997 can lead to severe consequences for systems processing untrusted ChemKin files with affected versions of Open Babel. The primary impact includes denial of service, as the application processing the malicious file will likely crash due to memory corruption. More critically, sophisticated exploitation could lead to arbitrary code execution, granting attackers control over the compromised system. Open Babel is widely integrated, being shipped by Linux distributions and embedded in various services that parse chemical file formats. Organizations using Open Babel in such contexts, especially those handling external or untrusted data, are at risk.

## Recommendation

*   Patch CVE-2025-10997 by upgrading all instances of Open Babel and its language bindings to version 3.2.0 or later immediately.
*   Implement strict input validation and sanitization for all ChemKin files processed by applications utilizing Open Babel components to mitigate risks from specially crafted inputs.
*   Monitor systems that utilize Open Babel for unexpected application crashes or unusual process behavior that could indicate attempted exploitation.
