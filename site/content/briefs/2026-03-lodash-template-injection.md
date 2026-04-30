---
title: lodash _.template Function Injection Vulnerability (CVE-2026-4800)
slug: 2026-03-lodash-template-injection
description: CVE-2026-4800 allows attackers to inject arbitrary code at template compilation time via untrusted input passed as key names in the options.imports object of the _.template function in lodash versions prior to 4.18.0, potentially leading to remote code execution.
date: "2026-03-31T20:16:29Z"
severities:
  - critical
type: advisory
types:
  - advisory
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

CVE-2026-4800 exposes a critical vulnerability within the `_.template` function of the lodash library in versions prior to 4.18.0. This vulnerability arises from insufficient validation when processing user-supplied input within the `options.imports` object. Specifically, while a fix for CVE-2021-23337 addressed validation for the `variable` option, it failed to extend the same rigorous checks to the key names within `options.imports`. Attackers can exploit this oversight by injecting malicious default-parameter expressions as key names in `options.imports`, triggering arbitrary code execution during the template compilation phase. This poses a significant risk, especially in applications that accept untrusted input to configure lodash templates, potentially leading to full system compromise. Furthermore, the vulnerability can be exacerbated if the `Object.prototype` is polluted, allowing inherited properties to be injected into the `imports` object, increasing the attack surface.

## Attack Chain

1. The application receives untrusted input intended for use in a lodash template.
2. The attacker crafts a malicious payload containing JavaScript code within the key names of the `options.imports` object. This payload leverages the default parameter expression vulnerability.
3. The application passes the attacker-controlled `options.imports` object to the `_.template` function.
4. The `_.template` function processes the `options.imports` without proper validation of the key names.
5. The `assignInWith` function merges the provided imports, including the attacker-controlled key names and their malicious content, into the template context.
6. During template compilation, the JavaScript `Function()` constructor is invoked, embedding the attacker's injected code.
7. The injected code executes within the context of the application, granting the attacker arbitrary code execution.
8. The attacker can leverage this code execution to perform actions such as installing malware, exfiltrating sensitive data, or compromising other parts of the system.

## Impact

Successful exploitation of CVE-2026-4800 can lead to arbitrary code execution on the server or client machine where the vulnerable application is running. The severity of this vulnerability is high, as it allows attackers to potentially gain full control of the affected system. The number of potential victims is broad, including any application using a vulnerable version of lodash and processing untrusted input in template configurations. This could affect various sectors, including web applications, APIs, and server-side rendering frameworks. A successful attack could result in data breaches, service disruptions, and complete system compromise.

## Recommendation

*   Upgrade to lodash version 4.18.0 or later to patch CVE-2026-4800, which implements proper validation for `options.imports`.
*   Implement strict input validation on any data used to construct `options.imports` objects to prevent injection attacks.
*   Apply the workaround by only using developer-controlled, static key names in `options.imports` to avoid passing untrusted input as key names.
*   Deploy the Sigma rule `Detect Lodash Template Injection via options.imports` to identify potential exploitation attempts in your environment.
