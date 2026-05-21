---
title: Twig RCE via Macro-Reference Compilation (CVE-2026-46640)
slug: 2026-05-twig-rce
description: A vulnerability in Twig versions 3.15.0 to 3.26.0 (CVE-2026-46640) allows arbitrary PHP code execution via the `_self.(<string>)` macro-reference compilation, enabling attackers to inject and execute arbitrary PHP code by supplying malicious template source, bypassing the SandboxExtension.
date: "2026-05-21T21:32:18Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - rce
  - twig
  - php
  - code-injection
vendors:
  - Composer
products:
  - Twig (>= 3.15.0, < 3.26.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://github.com/advisories/GHSA-45vw-wh46-2vx8
rules:
  - title: Detect Twig RCE via Macro Injection (CVE-2026-46640)
    description: Detects CVE-2026-46640 exploitation — attempts to inject PHP code via Twig macro injection by identifying suspicious patterns in HTTP requests targeting Twig templates.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
  - title: Detect Twig RCE via eval-like Functions (CVE-2026-46640)
    description: Detects CVE-2026-46640 exploitation — usage of eval, assert, or create_function within Twig templates, indicating a potential RCE attempt
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 2
---

A critical security flaw exists in Twig, a templating engine for PHP, specifically affecting versions 3.15.0 up to (but not including) 3.26.0. The vulnerability, identified as CVE-2026-46640, stems from the `obj.(expr)` dynamic-attribute syntax, which was introduced in version 3.15.0 as a replacement for the deprecated `attribute()` function. When the receiver is `_self` or an imported alias, and the expression is a string literal, the `DotExpressionParser` incorrectly concatenates the attacker-controlled string into a `MacroReferenceExpression` without proper validation. This bypasses the `SandboxExtension`, even with a globally-enabled sandbox and an empty `SecurityPolicy` allowlist. An attacker who can control the template source can inject arbitrary PHP code into the compiled template, resulting in code execution at template-load time.

## Attack Chain

1.  The attacker gains the ability to supply template source code to the Twig engine. This could be achieved through methods like exploiting an existing file upload vulnerability or directly manipulating template files if access is available.
2.  The attacker crafts a malicious template containing the `_self.(<string>)` syntax, where `<string>` is a PHP code injection payload. For example, `_self.("system('whoami')")`.
3.  The Twig engine parses the malicious template, and the `DotExpressionParser` handles the `_self.(<string>)` expression.
4.  The `DotExpressionParser` incorrectly concatenates the attacker-controlled string into a `MacroReferenceExpression` name without identifier validation, creating a malicious macro reference.
5.  The `MacroReferenceExpression::compile()` method then emits this raw, unvalidated name directly into the generated PHP source code.
6.  The Twig engine loads and compiles the generated PHP source code, effectively executing the injected PHP code.
7.  The injected PHP code executes system commands (e.g., `whoami`) or performs other malicious actions.
8.  The attacker gains unauthorized access to the system or data, potentially leading to further compromise, such as data exfiltration or lateral movement.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary PHP code on the server, leading to complete system compromise. This can result in data breaches, service disruption, and potential financial loss. Given the widespread use of Twig in PHP-based web applications, a significant number of systems are potentially vulnerable. The bypass of `SandboxExtension` makes this particularly dangerous, as it circumvents common security measures intended to restrict code execution.

## Recommendation

*   Upgrade to Twig version 3.26.0 or later to patch CVE-2026-46640, as recommended in the GitHub advisory ([https://github.com/advisories/GHSA-45vw-wh46-2vx8](https://github.com/advisories/GHSA-45vw-wh46-2vx8)).
*   Implement strict input validation and sanitization on any user-supplied data used in Twig templates to mitigate code injection risks.
*   Deploy the Sigma rule "Detect Twig RCE via Macro Injection (CVE-2026-46640)" to identify exploitation attempts in web server logs.
