---
title: lodash _.template Function Injection Vulnerability (CVE-2026-4800)
slug: 2026-03-lodash-template-injection
description: CVE-2026-4800 allows attackers to inject arbitrary code at template compilation time via untrusted input passed as key names in the options.imports object of the _.template function in lodash versions prior to 4.18.0, potentially leading to remote code execution.
date: "2026-03-31T20:16:29Z"
severities:
  - critical
tags:
  - lodash
  - template-injection
  - rce
  - cve-2026-4800
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
cves:
  - id: CVE-2026-4800
    cvss: 8.1
  - id: CVE-2021-23337
    cvss: 7.2
    epss: 0.04314
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4800
  - https://github.com/advisories/GHSA-35jh-r3h4-6jhm
rules:
  - title: Detect Lodash Template Injection via options.imports
    description: Detects potential attempts to exploit CVE-2026-4800 by identifying suspicious patterns in process command lines that could indicate injection into lodash templates via options.imports.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect Lodash Template Injection via eval-like expressions
    description: Detects eval-like patterns within command-line arguments that might signify attempts to inject code via template parsing in lodash.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-4800 exposes a critical vulnerability within the `_.template` function of the lodash library in versions prior to 4.18.0. This vulnerability arises from insufficient validation when processing user-supplied input within the `options.imports` object. Specifically, while a fix for CVE-2021-23337 addressed validation for the `variable` option, it failed to extend the same rigorous checks to the key names within `options.imports`. Attackers can exploit this oversight by injecting malicious…
