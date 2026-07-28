---
title: Datamodel Code Generator Vulnerable to Python Code Injection via GraphQL Schema
slug: 2026-07-datamodel-code-generator-code-injection
description: "`datamodel-code-generator` versions prior to `0.60.1` are vulnerable to code injection when processing attacker-controlled GraphQL schemas. An unescaped carriage return (`\r`) within a GraphQL Union type description (regular-string form) causes a generated Python comment to prematurely terminate, allowing arbitrary Python code, embedded after the carriage return in the description, to be parsed and executed as module-level code when the generated `.py` file is imported, leading to arbitrary code execution within the context of the importing process."
date: "2026-07-28T21:37:48Z"
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
  - graphql
  - cve
vendors:
  - datamodel-code-generator
products:
  - datamodel-code-generator >= 0.25.0, < 0.60.1
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who can provide or influence a GraphQL schema processed by `datamodel-code-generator` could cause arbitrary Python code to be generated into the output file. That code would execute with the privileges of the process importing the generated model.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-j884-q54q-mmx3
---

A code injection vulnerability (CVE-2026-54621) has been identified in `datamodel-code-generator` versions `>=0.25.0, <0.60.1`. This vulnerability allows an attacker to embed arbitrary Python code into generated models by crafting a malicious GraphQL schema. Specifically, if a GraphQL Union type description, provided as a regular string, contains an unescaped carriage return (`\r`), `datamodel-code-generator`'s Jinja2 template rendering process fails to properly escape this character. Python's lexical analyzer treats `\r` as a physical-line terminator, prematurely ending the intended comment and parsing the subsequent attacker-controlled text as executable module-level Python code. This injected code then executes when any consumer imports the generated `.py` model file, without requiring special CLI flags or custom templates. This vulnerability poses a significant risk to developers and CI/CD pipelines that process untrusted or third-party GraphQL schemas, potentially leading to supply chain compromise.

## Attack Chain

1. **Craft Malicious Schema**: An attacker crafts a GraphQL schema containing a Union type.
2. **Embed Code in Description**: Within the Union type's description (using the regular-string form), the attacker embeds a literal carriage return (`\r`) followed by arbitrary Python code (e.g., `...\rimport os; os.system('malicious_command')`).
3. **Code Generation**: A developer, CI pipeline, or application processes this malicious GraphQL schema using `datamodel-code-generator` (versions `>=0.25.0, <0.60.1`) to generate Python data models.
4. **Improper Comment Termination**: During the generation, `datamodel-code-generator` attempts to render the description as a Python comment but fails to normalize the `\r`.
5. **Python Lexical Analysis**: Python's tokenizer interprets the unescaped `\r` as a line terminator, prematurely ending the comment.
6. **Code Injection**: The attacker-controlled Python code, initially intended to be part of the comment, is now parsed as module-level Python code.
7. **Malicious File Creation**: `datamodel-code-generator` saves the generated `.py` file containing this injected, executable Python code.
8. **Code Execution**: When any process imports this newly generated `.py` model file, the injected Python code executes in the context of the importing process, achieving arbitrary code execution.

## Impact

An attacker capable of providing or influencing a GraphQL schema processed by vulnerable versions of `datamodel-code-generator` can achieve arbitrary code execution. This means they can inject and execute any Python code with the privileges of the process that imports the generated model. This directly impacts developers, continuous integration (CI) pipelines, and applications that automate the generation of Python models from GraphQL schemas, especially if these schemas originate from untrusted or third-party sources. The successful exploitation of this vulnerability could lead to supply chain attacks, data exfiltration, system compromise, or further lateral movement within an organization's development or production environment.

## Recommendation

* **Upgrade `datamodel-code-generator`**: Immediately upgrade to `datamodel-code-generator` version `0.60.1` or later to remediate CVE-2026-54621.
* **Review Schema Sources**: Implement strict validation and source control for GraphQL schemas, especially those used by `datamodel-code-generator` in automated pipelines.
* **Monitor Python Imports**: Enhance logging and monitoring for suspicious module imports or unexpected code execution events originating from dynamically generated Python files, which could indicate exploitation of vulnerabilities similar to CVE-2026-54621.
