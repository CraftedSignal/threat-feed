---
title: '`datamodel-code-generator` Vulnerable to Code Injection via `default_factory` Field'
slug: 2026-07-datamodel-code-generator-rce
description: The `datamodel-code-generator` library is vulnerable to code injection (CVE-2026-54653) when generating Python models from attacker-controlled schemas (e.g., JSON Schema, OpenAPI, YAML). This occurs because the `default_factory` schema field's value is interpolated directly as a raw Python expression into the generated code, allowing an attacker who controls the input schema to achieve arbitrary Python code execution within the consumer's process at module import time, affecting developers or CI pipelines that process untrusted schemas.
date: "2026-07-28T21:54:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - supply-chain
  - developer-tools
  - python
  - rce
  - cve
vendors:
  - datamodel-code-generator
products:
  - datamodel-code-generator (>= 0.17.0, <= 0.60.1)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary Python code execution in the importer's process at `import` time
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-386q-5hp3-95m9
iocs:
  - type: url
    value: https://gist.github.com/thegr1ffyn/9648b0fe4fcf7d569ac8e61dd11eebaf
ioc_counts:
  url: 1
---

`datamodel-code-generator` versions 0.17.0 through 0.60.1 are affected by a high-severity code injection vulnerability (CVE-2026-54653) that allows for arbitrary Python code execution. This vulnerability arises when the tool generates Python models from an attacker-controlled JSON Schema, OpenAPI, YAML, JSON, Avro, Protobuf, or XSD schema. Specifically, if a property within the input schema contains a `"default_factory"` key, its value is interpolated verbatim as a raw Python expression into the generated `Field(default_factory=...)` or `field(default_factory=...)` call. This code executes at class-definition time when the generated Python module is imported by a consumer. No special CLI flags are required for exploitation, making any developer or CI pipeline processing untrusted schemas susceptible. The fix involves validating `default_factory` values to only accept `dict`, `list`, and `set`.

## Attack Chain

1. An attacker crafts a malicious schema (e.g., JSON Schema, OpenAPI, YAML) containing a `"default_factory"` key with arbitrary Python code as its value.
2. A victim developer or CI pipeline uses `datamodel-code-generator` (versions 0.17.0 through 0.60.1) to generate Python data models from this attacker-controlled schema.
3. During code generation, the `datamodel-code-generator` parser (e.g., `jsonschema.py`) identifies the `"default_factory"` key.
4. The value associated with `"default_factory"` is retrieved from `self.extras` within the `JsonSchemaObject`.
5. When constructing the Python model (e.g., Pydantic v2, dataclass, msgspec), `datamodel-code-generator` interpolates the raw, unvalidated `default_factory` value directly into the generated Python code without sanitization.
6. The victim's Python application or environment imports the newly generated Python module.
7. Upon import, the interpolated malicious Python code embedded in the `default_factory` argument is executed at class-definition time within the importing process, leading to arbitrary code execution.
8. The attacker achieves their objective, such as filesystem reads (e.g., copying `/etc/passwd`), environment variable exfiltration, or secondary network calls.

## Impact

This vulnerability poses a significant supply chain risk to developers and CI pipelines. Any environment that uses `datamodel-code-generator` to process schemas not authored internally (e.g., third-party API specs, public schema registries, vendored files, remote introspection endpoints) is directly affected. Successful exploitation leads to arbitrary Python code execution within the importing process at module import time. This can result in data exfiltration, system compromise (e.g., filesystem read/write, network access), or further malicious activity on CI runners where build environments often have elevated privileges. While `typing.TypedDict` output models are not vulnerable, all other supported output model types, including Pydantic v2, dataclasses, and msgspec, are susceptible.

## Recommendation

* Upgrade `datamodel-code-generator` to version `0.60.2` or later immediately to patch CVE-2026-54653.
* Review CI/CD pipelines and developer workstations to ensure all instances of `datamodel-code-generator` are updated.
* Implement controls to validate or restrict the source of schemas used for code generation, especially those from external or untrusted origins.
* Monitor for unexpected process execution or file system modifications originating from Python processes that have recently imported newly generated data models, particularly if untrusted schemas are processed.
