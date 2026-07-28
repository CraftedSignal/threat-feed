---
title: datamodel-code-generator Vulnerable to Remote Code Execution via Template Data
slug: 2026-07-datamodel-code-generator-rce
description: The datamodel-code-generator tool, when configured for Pydantic v2 output and utilizing the --extra-template-data option, is vulnerable to arbitrary code execution (CVE-2026-54656) by injecting unescaped Python expressions into generated Pydantic field validators, leading to remote code execution (RCE) in the developer's interpreter or CI/CD environment upon module import.
date: "2026-07-28T21:45:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - python
  - code-generation
  - rce
  - supply-chain
  - vulnerability
  - template-injection
vendors:
  - datamodel-code-generator
products:
  - datamodel-code-generator (>= 0.52.1, <= 0.60.1)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The expression is evaluated at class-definition time, i.e. the moment the developer imports the generated module. This is... full RCE
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8m8r-38jm-f355
---

A critical remote code execution vulnerability (CVE-2026-54656, GHSA-8m8r-38jm-f355) has been identified in `datamodel-code-generator`, a Python tool used to generate Pydantic models from data schemas. Affecting versions 0.52.1 through 0.60.1, the flaw arises when the tool is configured for Pydantic v2 output and processes `--extra-template-data` containing a maliciously crafted `validators` entry. The tool unescapes input within this entry, allowing an attacker to inject arbitrary Python expressions into the generated `Pydantic @field_validator` decorator. This injected code executes with full RCE privileges within the developer's environment (e.g., interpreter or CI/CD runner) at the moment the generated Python module is imported. This vulnerability poses a significant supply chain risk for organizations that integrate `datamodel-code-generator` into their build processes, particularly if they accept template data from untrusted sources such as pull requests, public configuration snippets, or multi-tenant CI environments.

## Attack Chain

1. **Attacker crafts malicious template data**: An attacker creates a `--extra-template-data` file containing a `validators` entry with unescaped Python code injected into the `fields` or `mode` parameters.
2. **Developer uses `datamodel-code-generator`**: A developer or automated system runs the `datamodel-code-generator` tool, targeting a Pydantic v2 output mode and specifying the attacker's crafted `--extra-template-data` file.
3. **Tool processes malicious input**: The `datamodel-code-generator` tool, specifically within the `_process_validators` function in `src/datamodel_code_generator/model/pydantic_v2/base_model.py`, interpolates the unescaped malicious strings directly into the Python code for the generated `Pydantic @field_validator` decorator.
4. **Malicious Python code is embedded**: The tool generates and writes a new Python module (e.g., `BaseModel.jinja2`) which includes the attacker's injected arbitrary Python expression within the `field_validator` decorator call.
5. **Developer imports generated module**: The developer or a downstream system attempts to import the newly generated Python module into their environment.
6. **Arbitrary code execution**: At the time of module import, the Python interpreter evaluates the malicious expression embedded within the `@field_validator` decorator, leading to arbitrary code execution within the context of the importing process.
7. **Impact on development environment**: The attacker's code executes on the developer's machine or the CI/CD runner, allowing for actions such as data exfiltration, further system compromise, or manipulation of the software supply chain.

## Impact

Successful exploitation of CVE-2026-54656 results in arbitrary code execution within the developer's interpreter or CI/CD runner the moment the generated Python module is imported. This grants attackers the ability to execute commands, exfiltrate sensitive data, install backdoors, or tamper with the build process. The vulnerability affects `datamodel-code-generator` versions `>= 0.52.1` and `<= 0.60.1`. This impact is significantly higher than the previously discovered GHSA-wjv6-jcfj-mf9r, which allowed for docstring injection, as this vulnerability provides silent remote code execution under the same threat model. Organizations accepting `--extra-template-data` from untrusted sources in their development pipelines are directly at risk.

## Recommendation

* Upgrade `datamodel-code-generator` to version `0.60.2` or later immediately to remediate `CVE-2026-54656`.
* Restrict the use of the `--extra-template-data` option in `datamodel-code-generator` to trusted sources only, especially for affected versions `>= 0.52.1, <= 0.60.1`.
