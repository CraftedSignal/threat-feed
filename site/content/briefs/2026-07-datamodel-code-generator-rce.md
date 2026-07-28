---
title: '`datamodel-code-generator` Vulnerable to Code Execution via `x-python-type` Extension'
slug: 2026-07-datamodel-code-generator-rce
description: The `datamodel-code-generator` tool, versions 0.51.0 through 0.60.1, is vulnerable to remote code execution (RCE) via CVE-2026-54655 when processing untrusted JSON Schemas containing a specially crafted `x-python-type` extension, allowing an attacker to embed arbitrary Python statements that execute at class-definition time upon import of the generated module, impacting developer workstations and CI runners.
date: "2026-07-28T21:38:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-execution
  - supply-chain
  - vulnerability
  - json-schema
  - python
vendors:
  - datamodel-code-generator
products:
  - datamodel-code-generator >= 0.51.0, <= 0.60.1
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who controls a JSON Schema fed to `datamodel-codegen` can therefore embed an arbitrary Python statement in the generated module, which executes at class-definition time the moment the developer imports the file.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1580
    technique_name: Code Signing
    evidence: 'The compromise is silent: the schema is valid JSON, the generator emits syntactically clean Python (the trojan statement is a single indented line in the class body), and only the *use* of the generated file triggers the payload.'
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Arbitrary code execution in the developer's interpreter / CI runner as soon as the generated module is imported.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m34r-v34r-rf9q
---

The `datamodel-code-generator` tool, versions 0.51.0 through 0.60.1, is susceptible to a high-severity code execution vulnerability, CVE-2026-54655, affecting development environments and CI/CD pipelines. This vulnerability, discovered by Hamza Haroon, stems from inadequate sanitization of the `x-python-type` JSON-Schema extension. An attacker who controls the input JSON Schema can inject arbitrary Python statements into the generated data models. These malicious statements execute silently at class-definition time when the generated Python module is imported, leading to arbitrary code execution on developer workstations or CI runners. This silent compromise is particularly dangerous for organizations that ingest third-party or customer-supplied schemas, as it can enable supply chain attacks without requiring `--extra-template-data` or special flags.

## Attack Chain

1. An attacker creates or modifies a JSON Schema to include a malicious `x-python-type` extension for a field, containing arbitrary Python code (e.g., `X[1]; import os; os.system('calc.exe')`).
2. A developer or automated CI/CD pipeline uses `datamodel-code-generator` version 0.51.0 through 0.60.1 to generate Python data models from the attacker-controlled JSON Schema.
3. The `datamodel-code-generator` tool, due to insufficient sanitization of `x-python-type` values, embeds the arbitrary Python code directly into the generated Python file as part of a type annotation within a class definition.
4. The generated Python module, now containing the embedded malicious code, is saved to disk in the developer's environment or CI runner.
5. At a later stage, the developer's interpreter or a subsequent step in the CI/CD pipeline imports the generated Python module into a running Python application or script.
6. During the module import process, specifically at the class-definition time, the embedded Python code is executed by the interpreter.
7. The attacker's arbitrary Python code executes on the victim's system (developer workstation or CI runner), achieving arbitrary code execution.

## Impact

This vulnerability leads to arbitrary code execution in the developer's interpreter or CI runner as soon as the generated Python module is imported. The attack is silent; the crafted schema remains valid JSON, the generated Python is syntactically correct (the malicious statement is an indented line in the class body), and the payload only triggers upon use of the generated file. This impacts any workflow that processes untrusted JSON Schemas, including OpenAPI or JSON-Schema documents from third-party services, customer-supplied schemas in B2B platforms, or schemas within a malicious commit in a polyglot repository triggering CI code generation. The primary blast radius includes CI runners and developer workstations, exposing sensitive environments to compromise.

## Recommendation

* Upgrade to `datamodel-code-generator` version `0.60.2` or later immediately to mitigate CVE-2026-54655.
* Implement strict validation and static analysis for JSON Schemas ingested from untrusted or external sources to identify suspicious `x-python-type` extensions.
