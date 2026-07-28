---
title: datamodel-code-generator Vulnerable to Arbitrary Local File Read via XSD Path Traversal
slug: 2026-07-datamodel-code-generator-path-traversal
description: datamodel-code-generator versions 0.59.0 through 0.61.0 are vulnerable to an unauthenticated path traversal and information disclosure issue, allowing an attacker to read arbitrary local files on the system where the code generator is executed by crafting a malicious XML Schema (XSD) `schemaLocation` attribute, with the contents of the files then incorporated into the generated output.
date: "2026-07-28T21:34:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - information-disclosure
  - supply-chain
  - vulnerability
vendors:
  - koxudaxi
products:
  - datamodel-code-generator (>= 0.59.0, <= 0.61.0)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An attacker who controls the input XSD can read arbitrary files via `../` traversal or an absolute path, and the included schema's contents (type names, restrictions, enumerations) are folded into the generated output.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-442q-2j6p-642g
  - https://github.com/koxudaxi/datamodel-code-generator-ghsa-442q-2j6p-642g/pull/1
  - https://gist.github.com/thegr1ffyn/c7096b797926348875d888652867eeb4
---

Versions 0.59.0 through 0.61.0 of `datamodel-code-generator`, a tool for generating data models, contain a high-severity path traversal vulnerability (CVE-2026-55390). When processing an attacker-controlled XML Schema Definition (XSD) file, the tool fails to properly sanitize `schemaLocation` attributes within `<xs:include>`, `<xs:import>`, `<xs:redefine>`, and `<xs:override>` elements. This allows an attacker to specify relative paths using `../` or absolute paths, enabling the `datamodel-code-generator` process to read arbitrary files outside the intended project directory. The contents of these external files are subsequently incorporated into the generated Python models, leading to information disclosure. The default configuration is affected, and existing `--no-allow-remote-refs` options do not mitigate this specific XSD-based vector, making it a significant risk for applications and CI pipelines that process untrusted XSD input.

## Attack Chain

1. An attacker crafts a malicious XSD file containing an `<xs:include>` or `<xs:import>` element with a `schemaLocation` attribute.
2. The `schemaLocation` attribute is set to either a path traversal sequence (e.g., `../../etc/passwd`) or an absolute path (e.g., `/var/log/apache2/access.log`).
3. The attacker convinces a victim to generate models using the malicious XSD file, for instance, by integrating it into a build pipeline or using it in a multi-tenant environment.
4. The victim executes `datamodel-codegen --input attacker.xsd --input-file-type xmlschema --output generated_models.py`.
5. During the XSD parsing process, `datamodel-code-generator` resolves the malicious `schemaLocation`.
6. Due to the vulnerability, the tool reads the content of the arbitrary local file specified in the `schemaLocation`.
7. The content of the sensitive file is then folded into the generated Python output file (`generated_models.py`).
8. The attacker subsequently obtains the generated output, thereby exfiltrating the contents of the sensitive local file.

## Impact

This vulnerability (CVE-2026-55390) enables arbitrary local file read (CWE-22) leading to significant information disclosure (CWE-200). Any environment that uses `datamodel-code-generator` to process untrusted XML Schema Definition (XSD) files is at risk. This includes development workflows, CI/CD pipelines, and multi-tenant services where an attacker can supply an XSD. Attackers can read sensitive files such as configuration files, source code, private keys, or system credentials. While verbatim disclosure is guaranteed for XML/XSD-shaped data, the tool reads raw bytes of any file, making it a potent primitive for arbitrary file access. The compromised data, once incorporated into generated models, can be exfiltrated via various means, such as being committed to a repository, logged, or returned by a service.

## Recommendation

* Upgrade `datamodel-code-generator` to version `0.62.0` or newer immediately to address CVE-2026-55390.
* Implement checks to reject resolved `schemaLocation` targets that are not strictly relative to the base path when processing XSD files in any custom integration.
* Ensure that any automated systems or services processing untrusted XSD files run with the principle of least privilege, limiting their access to sensitive file system locations.
