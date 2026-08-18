---
title: Remote Code Execution in jmespath.php via CompilerRuntime
slug: 2026-08-jmespath-injection
description: The mtdowling/jmespath.php library contains a critical code injection vulnerability, CVE-2026-54133, allowing attackers to execute arbitrary PHP code when untrusted JMESPath expressions are processed by the CompilerRuntime.
date: "2026-08-18T20:56:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:jmespath:jmespath:*:*:*:*:*:php:*:*
tags:
  - remote-code-execution
  - php
  - code-injection
vendors:
  - mtdowling
products:
  - jmespath.php
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An attacker can execute arbitrary PHP code with the privileges of the PHP process.
    confidence_band: high
cves:
  - id: CVE-2026-54133
    cvss: 9.8
    epss: 0.0032
references:
  - https://github.com/advisories/GHSA-pcw8-m77r-2528
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54133
---

The mtdowling/jmespath.php library is susceptible to a code injection vulnerability (CVE-2026-54133) affecting versions prior to 2.9.1. The vulnerability exists within the `CompilerRuntime` component, which is designed to optimize performance by compiling JMESPath expressions into PHP code before execution. An attacker who can provide input to an application that uses this library can craft a malicious JMESPath expression containing a non-identifier value in a function call position. Because the library fails to properly escape these function names before writing them into generated PHP cache files, the injected code is interpreted and executed by the PHP engine when the cache file is loaded. This vulnerability is triggered either through explicit use of `JmesPath\CompilerRuntime` or by enabling the `JP_PHP_COMPILE` environment variable, which forces the usage of the compiler. Successful exploitation leads to remote code execution under the privileges of the web server process.

## Attack Chain

1. An attacker identifies an application endpoint that accepts user-supplied JMESPath expressions for data transformation or filtering.
2. The application is confirmed to be using `mtdowling/jmespath.php` versions < 2.9.1.
3. The attacker provides a crafted JMESPath expression string designed to exploit the missing escaping logic in the compiler.
4. The library's `CompilerRuntime` parses the expression and generates a temporary PHP cache file containing the attacker's injected payload.
5. The application triggers the execution of the compiled expression, causing the PHP engine to include and evaluate the malicious cache file.
6. The injected payload executes within the application process context.
7. The attacker gains the ability to execute arbitrary PHP code, potentially leading to system compromise or data exfiltration.

## Impact

The vulnerability allows unauthenticated or authenticated attackers (depending on the application's input exposure) to achieve remote code execution. Given that this library is a standard tool for handling JSON-like data in PHP applications, the potential scope includes any web application enabling `JP_PHP_COMPILE` or explicitly using the `CompilerRuntime` to process untrusted user input. Success results in full control over the application's PHP process, providing a path to access local files, modify application logic, or pivot deeper into the internal network.

## Recommendation

* Upgrade `mtdowling/jmespath.php` to version 2.9.1 or later to remediate CVE-2026-54133.
* If upgrading is not immediately possible, disable the `JP_PHP_COMPILE` environment variable across all application environments to force the use of the safer `AstRuntime`.
* Audit application code to identify usages of `JmesPath\CompilerRuntime` and ensure that no user-controlled input is ever passed to these instances without rigorous validation.
* Implement strict input validation or use allowlists for any JMESPath expressions accepted from external sources to prevent the injection of malicious characters.
