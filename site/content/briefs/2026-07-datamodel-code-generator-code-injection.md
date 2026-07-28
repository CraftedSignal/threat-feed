---
title: datamodel-code-generator Vulnerable to Code Injection via Unescaped Carriage Return
slug: 2026-07-datamodel-code-generator-code-injection
description: The `datamodel-code-generator` Python package is vulnerable to code injection (CVE-2026-54654) when a developer uses the `--extra-template-data` option with a file whose `comment` value contains an unescaped carriage return, leading to arbitrary Python code execution during the import process of the generated code.
date: "2026-07-28T21:52:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-injection
  - supply-chain
  - rce
  - python
  - vulnerability
vendors:
  - datamodel-code-generator project
products:
  - datamodel-code-generator (0.14.1 to 0.60.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary Python code execution in the importer's process at `import` time.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wjv6-jcfj-mf9r
  - https://docs.python.org/3/reference/lexical_analysis.html#physical-lines
---

The `datamodel-code-generator` Python package, specifically versions between `0.14.1` and `0.60.1` inclusive, contains a critical code injection vulnerability, CVE-2026-54654. This flaw allows arbitrary Python code execution during the import of generated code when a developer utilizes the `--extra-template-data` command-line option with an input file containing a maliciously crafted `comment` field. If this `comment` field includes an unescaped carriage return (`\r`), Python's tokenizer treats it as a line terminator, allowing subsequent text to be parsed as executable Python code instead of remaining within a comment block. This poses a significant risk to developers and CI/CD pipelines that process untrusted or attacker-controlled input in their `--extra-template-data` files, potentially leading to supply chain compromises and remote code execution in development environments.

## Attack Chain

1. An attacker crafts a malicious `--extra-template-data` file.
2. The malicious file's `comment` field contains a literal carriage return (`\r`) followed by arbitrary Python code.
3. A developer or CI/CD pipeline invokes `datamodel-code-generator` (versions `0.14.1` to `0.60.1`) with the `--extra-template-data` option pointing to the malicious file.
4. The `datamodel-code-generator` uses Jinja2 templates, which interpolate the `comment` value directly without escaping line terminators.
5. The generated Python code file will contain the unescaped carriage return within what should be a comment line.
6. When this generated Python file is subsequently imported by a Python interpreter, the bare `\r` acts as a physical line terminator.
7. The Python interpreter ceases treating the line as a comment after the `\r` and parses the attacker-controlled Python code that follows.
8. This results in arbitrary Python code execution within the context of the importing process, achieving code injection.

## Impact

This vulnerability (CVE-2026-54654) affects any developer or CI pipeline that uses `datamodel-code-generator` versions between `0.14.1` and `0.60.1` and processes `--extra-template-data` files influenced by attacker-controlled input. Successful exploitation grants attackers arbitrary Python code execution within the developer's or build system's environment during the import phase of the generated code. This can lead to severe consequences, including intellectual property theft, unauthorized access to source code repositories, injection of malicious dependencies, and compromise of build artifacts, potentially affecting an organization's entire software supply chain. The vulnerability does not require the schema itself to be malicious, only the `comment` field in the extra template data.

## Recommendation

* Upgrade `datamodel-code-generator` to version `0.60.2` or later immediately to remediate CVE-2026-54654.
* Implement strict input validation for all `--extra-template-data` files, particularly the `comment` field, to prevent the inclusion of unescaped carriage returns (`\r`), vertical tabs (`\x0b`), or form feeds (`\x0c`) before invoking `datamodel-code-generator`.
* Review CI/CD pipelines and developer workflows that use `datamodel-code-generator` and process external or untrusted data sources to ensure such inputs are properly sanitized.
