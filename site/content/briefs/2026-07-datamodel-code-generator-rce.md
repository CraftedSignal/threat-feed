---
title: Datamodel-code-generator Remote Code Execution via Code Injection
slug: 2026-07-datamodel-code-generator-rce
description: A high-severity code injection vulnerability (CVE-2026-55415) in `datamodel-code-generator` versions 0.11.6 through 0.63.0 allows an unauthenticated attacker to achieve remote code execution by providing a specially crafted OpenAPI or JSON Schema that injects arbitrary Python code into generated import statements, which then executes when the generated model is imported.
date: "2026-07-28T21:41:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - rce
  - supply-chain
  - vulnerability
  - python
vendors:
  - koxudaxi
products:
  - datamodel-code-generator (>= 0.11.6, <= 0.63.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A malicious input schema (OpenAPI / JSON Schema) can execute arbitrary Python code on the machine that imports the generated model.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5578-w22f-pfx9
iocs:
  - type: file_path
    value: /etc/passwd
  - type: file_path
    value: /tmp/dmcg_xpi_loot
  - type: file_path
    value: /tmp/dmcg_ctp_loot
ioc_counts:
  file_path: 3
rules:
  - title: Detect CVE-2026-55415 Exploitation - datamodel-code-generator Arbitrary File Write
    description: Detects CVE-2026-55415 exploitation - creation of specific temporary files (`/tmp/dmcg_xpi_loot`, `/tmp/dmcg_ctp_loot`) by Python, as demonstrated in the proof-of-concept for remote code execution via datamodel-code-generator.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - file_event
      - linux
rules_count: 1
---

A high-severity code injection vulnerability (CVE-2026-55415) has been identified in `datamodel-code-generator`, a Python library used to generate data models from OpenAPI or JSON Schema specifications. Affecting versions from 0.11.6 up to 0.63.0, this flaw allows a malicious input schema to execute arbitrary Python code on the machine that imports the generated model. The `x-python-import` and `customTypePath` schema extensions are processed unsanitized into the library's `import` statements. By embedding a newline character in these extension values, an attacker can break out of the intended `from ... import ...` statement and inject arbitrary Python code at the module scope, which is then executed when the generated model is imported. This represents an unauthenticated, schema-content-driven remote code execution vector. The vulnerability was discovered by Hamza Haroon and is considered an incomplete fix, as a previous security release (v0.61.0) addressed similar issues but overlooked these specific code paths.

## Attack Chain

1. An attacker crafts a malicious OpenAPI or JSON Schema document.
2. The malicious schema utilizes the `x-python-import` or `customTypePath` extensions, embedding a newline character followed by attacker-controlled Python code (e.g., `getcwd\nprint(*open('/etc/passwd'),...)`).
3. A victim, or their automated tooling (e.g., CI/CD pipeline, multi-tenant code-generation service), processes the malicious schema using `datamodel-code-generator`.
4. The `datamodel-code-generator` library generates a Python model file (`model.py`) that includes the attacker's injected code as part of a `from ... import ...` statement within the module's global scope.
5. The generated `model.py` file is subsequently imported by the victim's application or development environment.
6. Upon import, the injected Python code executes automatically at module scope with the privileges of the importing process.
7. The attacker achieves remote code execution, demonstrated by the proof-of-concept exfiltrating `/etc/passwd` to a temporary file.

## Impact

The successful exploitation of CVE-2026-55415 leads to arbitrary code execution on the system at the time the generated Python model is imported. This affects anyone running `datamodel-code-generator` on untrusted or third-party schemas, including multi-tenant code-generation services, CI pipelines ingesting external specifications, or individual developers creating models from public OpenAPI/JSON-Schema documents. The attacker-controlled code executes with the privileges of the importing process, allowing for sensitive actions such as arbitrary file reading, system modification, or network-based exfiltration. The provided proof-of-concept demonstrates the ability to read `/etc/passwd`, confirming the severity of the remote code execution primitive.

## Recommendation

* Patch `datamodel-code-generator` to the version that includes the fix for CVE-2026-55415 immediately once available.
* Implement strict validation and sanitization for all external or untrusted OpenAPI/JSON Schema inputs processed by `datamodel-code-generator`.
* Deploy the Sigma rule "Detect CVE-2026-55415 Exploitation - `datamodel-code-generator` Arbitrary File Write" to your SIEM to detect attempts to write specific malicious output files demonstrated in the PoC.
* Monitor for `file_event` logs indicating suspicious file writes to `/tmp/dmcg_xpi_loot` or `/tmp/dmcg_ctp_loot` by Python processes, as these are indicators of exploitation.
