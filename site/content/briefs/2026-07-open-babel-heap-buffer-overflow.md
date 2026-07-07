---
title: Open Babel Heap Buffer Overflow in SMILES Parsing (CVE-2025-10996)
slug: 2026-07-open-babel-heap-buffer-overflow
description: A heap buffer overflow vulnerability (CVE-2025-10996) in Open Babel's `OBSmilesParser::ParseSmiles` function allows attackers to achieve denial of service or arbitrary code execution by crafting and supplying a malformed SMILES input string to affected versions up to 3.1.1.
date: "2026-07-03T13:02:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openbabel:open_babel:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - buffer-overflow
  - chemistry
  - library
  - cve
vendors:
  - Open Babel
products:
  - Open Babel (< 3.2.0)
affected_os:
  - Linux
  - Windows
  - macOS
cves:
  - id: CVE-2025-10996
    cvss: 5.3
    epss: 0.00224
references:
  - https://github.com/advisories/GHSA-j35x-w4gj-pf7w
  - https://github.com/openbabel/openbabel/commit/b34cd604
---

A critical memory-safety vulnerability, tracked as CVE-2025-10996, has been identified in Open Babel, a widely used C++ chemistry library and command-line tool. The flaw specifically resides within the `OBSmilesParser::ParseSmiles` function, which is responsible for interpreting SMILES (Simplified Molecular Input Line Entry Specification) strings. When processing a specially crafted and malformed SMILES input, the parser can write beyond the boundaries of a heap-allocated buffer, leading to a heap buffer overflow. This vulnerability affects all Open Babel versions up to and including 3.1.1. It is particularly concerning because Open Babel is often embedded in services that parse untrusted input and SMILES strings are frequently handled via command-line arguments and automated script pipelines, making the exploitation primitive easily reachable. A patch was released in version 3.2.0 on May 26, 2026, addressing the issue.

## Attack Chain

1.  **Attacker crafts malicious SMILES string**: The attacker develops a specially engineered SMILES string designed to exploit the heap buffer overflow vulnerability in Open Babel's `OBSmilesParser::ParseSmiles` function.
2.  **Attacker delivers malicious SMILES string**: The crafted SMILES string is delivered to the victim, potentially via a malicious file (e.g., a `.smi` file), an email attachment, or as input within a web application or scientific workflow.
3.  **Victim initiates SMILES parsing**: The victim, or an automated system, processes the malicious SMILES string using Open Babel through the `obabel` command-line tool, the `OBConversion` API, or any of its language bindings (Python, Ruby, Java, R, Perl, C#, PHP).
4.  **`OBSmilesParser::ParseSmiles` is invoked**: Open Babel's internal `OBSmilesParser::ParseSmiles` function is called to interpret the malformed SMILES input string.
5.  **Heap buffer overflow triggers**: During parsing, the specially crafted SMILES string causes the `ParseSmiles` function to write data beyond the allocated memory region on the heap.
6.  **Memory corruption and impact**: This heap buffer overflow leads to memory corruption, which can result in a denial-of-service (DoS) condition by crashing the application, or, if successfully manipulated, arbitrary code execution within the context of the vulnerable Open Babel process.
7.  **Post-exploitation (if RCE achieved)**: If arbitrary code execution is achieved, the attacker gains control over the compromised process, potentially enabling further actions such as data exfiltration, system compromise, or malware deployment.

## Impact

The exploitation of CVE-2025-10996 can lead to severe consequences for organizations utilizing Open Babel. At minimum, a successful attack will result in a denial-of-service (DoS) condition, causing the Open Babel application or any service embedding it to crash. More critically, skilled attackers could potentially leverage this heap buffer overflow to achieve arbitrary code execution, granting them unauthorized control over the affected system. Organizations in scientific research, chemical industries, and any sector relying on chemical data processing and Open Babel for parsing untrusted SMILES input are at risk. The broad deployment of Open Babel, including its presence in Linux distributions and various language bindings, expands the potential attack surface.

## Recommendation

*   Patch CVE-2025-10996 immediately by upgrading Open Babel to version 3.2.0 or later on all affected systems and integrated services.
*   Review all instances where Open Babel is used to parse external or untrusted SMILES input, especially those invoked via command-line or programmatic APIs.
