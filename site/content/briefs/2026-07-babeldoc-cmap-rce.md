---
title: BabelDOC Arbitrary Code Execution via CMap Pickle Deserialization
slug: 2026-07-babeldoc-cmap-rce
description: An arbitrary code execution vulnerability exists in BabelDOC's vendored PDF parser (`babeldoc/pdfminer/cmapdb.py`) due to insecure deserialization of untrusted pickle data, allowing an attacker to craft a PDF with a specially encoded '/Encoding' name containing an absolute path that bypasses directory restrictions, leading to deserialization and execution of a malicious '.pickle.gz' file on the local filesystem with the privileges of the BabelDOC process.
date: "2026-07-10T19:40:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-execution
  - deserialization
  - pdf
  - python
  - path-traversal
  - python
  - linux
  - windows
vendors:
  - funstory-ai
products:
  - BabelDOC <= 0.6.2
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Arbitrary Code Execution via CMap Pickle Deserialization in babeldoc/pdfminer/cmapdb.py
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary Python code execution with the privileges of the BabelDOC process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m8gf-v64p-gfmg
---

BabelDOC, specifically its vendored PDF parser located at `babeldoc/pdfminer/cmapdb.py`, is vulnerable to arbitrary code execution (ACE) through insecure pickle deserialization. This vulnerability, identified as a path injection issue, arises when processing CMap files within PDFs. The `_load_data()` method of `CMapDB` does not properly sanitize the CMap name extracted from a PDF. An attacker can craft a PDF with a hex-encoded absolute path (e.g., `/#2Ftmp#2Fattacker#2Fevil`) in the `/Encoding` name. Due to how Python's `os.path.join()` handles absolute paths, the attacker-controlled path will override the legitimate CMap directory, causing BabelDOC to load and deserialize a malicious `.pickle.gz` file placed by the attacker on the local system. This leads to arbitrary Python code execution with the privileges of the BabelDOC process, posing a significant risk to any user or automated pipeline processing untrusted PDF documents.

## Attack Chain

1. An attacker prepares a malicious Python pickle payload and writes it to a `.pickle.gz` file in a world-writable location on the victim's filesystem (e.g., `/tmp/malicious.pickle.gz`).
2. The attacker crafts a PDF document that includes a Type0 CID font definition with an `/Encoding` name object containing a hex-encoded absolute path pointing to the malicious `.pickle.gz` file (e.g., `/#2Ftmp#2Fmalicious`).
3. The victim's system, running BabelDOC (either via the CLI or an embedded application), processes the attacker's crafted PDF file.
4. BabelDOC's `pdfminer` component parses the PDF, and the `psparser` decodes the hex-encoded `/Encoding` name from the font definition into an absolute path string (e.g., `/tmp/malicious`).
5. This attacker-controlled absolute path is passed to `CMapDB._load_data()`, which constructs a full file path using `os.path.join(trusted_directory, attacker_path + ".pickle.gz")`. Because `attacker_path` is absolute, `os.path.join()` discards `trusted_directory`, resulting in the path `/tmp/malicious.pickle.gz`.
6. BabelDOC then attempts to open and decompress this file using `gzip.open()`, treating it as a legitimate CMap data file.
7. Subsequently, the contents of the decompressed file are passed to `pickle.loads()`, triggering the deserialization of the attacker's malicious Python object.
8. The arbitrary Python code embedded in the malicious pickle payload is executed with the privileges of the BabelDOC process, leading to system compromise, data exfiltration, or further malicious activity.

## Impact

This vulnerability leads to Arbitrary Code Execution, meaning an attacker can run any Python code on the affected system. This directly impacts end-users who interact with the `babeldoc` CLI or any applications integrating its PDF processing capabilities. Automated document processing pipelines, especially those ingesting untrusted PDFs (e.g., translation services, document management systems), are highly susceptible. The attack requires the ability to place a `.pickle.gz` file on a local writable path, which is a common scenario in multi-user systems. Successful exploitation results in full code execution with the privileges of the compromised BabelDOC process, potentially leading to confidentiality breaches, data modification, denial of service, and depending on the environment, privilege escalation or lateral movement across the network.

## Recommendation

* Upgrade BabelDOC to a patched version immediately to remediate the CVE-candidate vulnerability.
* Implement strong input validation and sanitization for all PDF inputs processed by BabelDOC, especially for name objects and file paths within the PDF structure.
* If immediate patching is not possible, apply the recommended patch to `babeldoc/pdfminer/cmapdb.py` to correctly validate and restrict paths for CMap loading.
* Monitor for unexpected file creations in system temporary directories (e.g., `/tmp/`) that end with `.pickle.gz` by processes like `python` or `babeldoc`.
* Restrict BabelDOC's execution environment using sandboxing technologies (e.g., Docker, virtual machines, or least privilege user accounts) to limit potential damage from successful arbitrary code execution.
