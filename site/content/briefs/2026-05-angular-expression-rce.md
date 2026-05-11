---
title: Angular Expressions Remote Code Execution via Malicious Filter
slug: 2026-05-angular-expression-rce
description: A remote code execution vulnerability (CVE-2026-44643) exists in angular-expressions versions 1.5.1 and earlier, allowing an attacker to execute arbitrary code on the system by crafting a malicious expression that bypasses the sandbox.
date: "2026-05-11T16:22:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - angular-expressions
  - cve-2026-44643
products:
  - angular-expressions (<= 1.5.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-44643
references:
  - https://github.com/advisories/GHSA-pw8r-6689-xvf4
  - CVE-2026-44643
rules:
  - title: Detect CVE-2026-44643 Exploitation — angular-expressions Sandbox Escape
    description: Detects CVE-2026-44643 exploitation — Attempts to exploit the angular-expressions sandbox escape vulnerability by detecting the use of '__proto__' in expressions.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detect CVE-2026-44643 Exploitation — angular-expressions SyntaxError
    description: Detects CVE-2026-44643 exploitation — Error resulting from attempts to exploit the angular-expressions sandbox escape vulnerability by detecting the 'Unexpected identifier Object' error.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 2
---

The `angular-expressions` library, up to version 1.5.1, is vulnerable to remote code execution. This vulnerability, identified as CVE-2026-44643, allows an attacker to craft a malicious expression that escapes the sandbox environment of the library. By exploiting this flaw, an attacker can execute arbitrary code on the system where the vulnerable library is used. This poses a significant risk to applications utilizing `angular-expressions` for expression evaluation, potentially leading to complete system compromise. The vulnerability was discovered by San Gil from SecurityOffice. Version 1.5.2 of `angular-expressions` contains the fix.

## Attack Chain

1. An attacker identifies an application using a vulnerable version (<= 1.5.1) of the `angular-expressions` library.
2. The attacker crafts a malicious expression designed to exploit the sandbox escape vulnerability.
3. The attacker injects the malicious expression into the application, potentially through user input or other application logic.
4. The application uses the `expressions.compile()` function to compile the malicious expression. For example: `expressions.compile("a | __proto__")({}, {})`
5. The vulnerable `angular-expressions` library fails to properly sanitize the expression, allowing it to bypass the sandbox restrictions.
6. The expression gains access to underlying JavaScript engine internals (e.g., `__proto__`).
7. The attacker leverages this access to execute arbitrary code on the server.
8. This arbitrary code execution could lead to complete compromise of the affected system, including data exfiltration, service disruption, or further lateral movement within the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the system hosting the application utilizing the vulnerable `angular-expressions` library. This can lead to complete system compromise, including data exfiltration, installation of malware, or denial of service. The severity is critical due to the potential for unauthenticated remote code execution.

## Recommendation

*   Upgrade the `angular-expressions` library to version 1.5.2 or later to patch CVE-2026-44643.
*   Deploy the Sigma rule `Detect CVE-2026-44643 Exploitation — angular-expressions Sandbox Escape` to detect attempts to exploit the vulnerability in web server logs.
*   Implement input validation to prevent the injection of malicious expressions into applications using `angular-expressions`.
*   Continuously monitor web server logs for suspicious activity related to expression compilation.
