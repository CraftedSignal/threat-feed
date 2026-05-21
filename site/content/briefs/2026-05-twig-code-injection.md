---
title: 'Twig: PHP Code Injection via `{% use %}` Template Name (CVE-2026-46633)'
slug: 2026-05-twig-code-injection
description: A code injection vulnerability (CVE-2026-46633) exists in Twig versions prior to 3.26.0, where a single quote in the `{% use %}` template name is not properly escaped, allowing arbitrary PHP code execution by bypassing the Twig sandbox.
date: "2026-05-21T21:26:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - twig
  - rce
vendors:
  - Composer
products:
  - twig/twig (< 3.26.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://github.com/advisories/GHSA-7p85-w9px-jpjp
  - CVE-2026-46633
rules:
  - title: Detect CVE-2026-46633 Exploitation — Twig Use Tag Code Injection
    description: Detects CVE-2026-46633 exploitation — A Twig template containing a `use` tag with a single quote in the template name may indicate a code injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
  - title: Detect CVE-2026-46633 Attempt — Twig Use Tag Code Injection with PHP function
    description: Detects CVE-2026-46633 exploitation attempts — A Twig template containing a `use` tag with a single quote and a PHP function call (e.g., phpinfo()) in the template name may indicate a code injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

A critical code injection vulnerability, tracked as CVE-2026-46633, affects Twig versions before 3.26.0. The vulnerability stems from insufficient escaping of single quotes within the `Compiler::string()` function when handling template names in `{% use %}` tags. Specifically, the `Compiler::string()` function escapes characters like `"` and `$` but fails to escape single quotes, which are later used within a PHP single-quoted string literal in `ModuleNode::compileConstructor()`. This oversight allows an attacker to inject arbitrary PHP code by including a single quote in the template name passed to the `{% use %}` tag. The injected code is then executed when the compiled Twig cache file is loaded, bypassing the configured `SecurityPolicy` and leading to remote code execution. The `{% use %}` tag is unconditionally allowed regardless of the `allowedTags` configuration, making this vulnerability reachable even from sandboxed templates.

## Attack Chain

1.  Attacker crafts a malicious Twig template containing a `{% use %}` tag.
2.  The template name within the `{% use %}` tag includes a single quote followed by arbitrary PHP code, e.g., `{% use 'x' . phpinfo() . 'y' %}`.
3.  The Twig template is rendered using a vulnerable version of Twig (<3.26.0).
4.  During compilation, the `ModuleNode::compileConstructor()` function processes the `{% use %}` tag and uses `Compiler::string()` to escape the template name.
5.  `Compiler::string()` fails to escape the single quote, allowing the attacker to break out of the surrounding PHP single-quoted string literal.
6.  The malicious PHP code is written into the compiled Twig cache file.
7.  The compiled Twig cache file is loaded by the PHP engine during subsequent template renderings.
8.  The injected PHP code executes within the PHP process, bypassing the Twig sandbox and achieving remote code execution.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary PHP code on the server hosting the Twig application. Given that the Twig sandbox is bypassed, attackers can perform a wide range of malicious actions, including reading sensitive files, modifying application data, and potentially gaining full control of the server. This vulnerability affects applications using Twig versions prior to 3.26.0.

## Recommendation

*   Upgrade to Twig version 3.26.0 or later to patch CVE-2026-46633.
*   Deploy the following Sigma rule to detect potential exploitation attempts by monitoring for the `use` tag containing a single quote (').
*   Review existing Twig templates for any instances of user-controlled input being used in `{% use %}` tags and sanitize the input to prevent code injection.
