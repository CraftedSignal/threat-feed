---
title: Math.js Improperly Controlled Modification of Object Attributes Leads to RCE
slug: 2026-04-mathjs-rce
description: A vulnerability in math.js versions before 15.2.0 allows for arbitrary JavaScript execution through the expression parser when evaluating user-supplied expressions.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mathjs
  - rce
  - expression-injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-jvff-x2qm-6286
  - https://github.com/josdejong/mathjs/releases/tag/v15.2.0
rules:
  - title: Detect Math.js Expression Injection Attempt via HTTP Query
    description: Detects potential expression injection attempts in math.js applications by monitoring HTTP query parameters for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Math.js Expression Injection Attempt via HTTP Body
    description: Detects potential expression injection attempts in math.js applications by monitoring HTTP request body for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Math.js is a popular open-source mathematics library for JavaScript. A critical vulnerability (GHSA-jvff-x2qm-6286) exists in versions prior to 15.2.0, allowing arbitrary JavaScript execution. This flaw stems from improperly controlled modification of dynamically-determined object attributes within the expression parser. Applications that utilize math.js to evaluate user-provided mathematical expressions are susceptible. The vulnerability was reported on April 10, 2026, and a patch was released in version 15.2.0. Successful exploitation could lead to complete compromise of the application's server-side environment, enabling data theft, system modification, or denial of service.

## Attack Chain

1. An attacker crafts a malicious mathematical expression designed to exploit the vulnerability in math.js.
2. The attacker submits the malicious expression to a vulnerable application that uses math.js for expression parsing.
3. The application's server-side code receives the input and passes it to the math.js `evaluate()` function.
4. The vulnerable `evaluate()` function processes the expression, leading to unintended modification of object attributes.
5. This modification triggers the execution of arbitrary JavaScript code embedded within the malicious expression.
6. The attacker's JavaScript code executes within the context of the server-side application, bypassing security controls.
7. The attacker gains unauthorized access to sensitive data, modifies system configurations, or installs malicious software.
8. The attacker achieves full remote code execution (RCE), compromising the entire application.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary JavaScript code on the server running the vulnerable application. This can result in complete system compromise, including unauthorized data access, data modification, and denial of service. If the compromised application has access to sensitive databases or internal systems, the attacker can pivot to further compromise the internal network. The vulnerability impacts any application using math.js < 15.2.0 and allows users to evaluate arbitrary expressions, with potentially widespread consequences depending on the application's role and permissions.

## Recommendation

*   Immediately upgrade math.js to version 15.2.0 or later to patch the vulnerability (GHSA-jvff-x2qm-6286).
*   If immediate patching is not possible, consider disabling or restricting user-provided expression evaluation functionalities.
*   Deploy the Sigma rules below to your SIEM to detect potential exploitation attempts against vulnerable math.js instances.
*   Monitor web server logs for suspicious patterns in user input indicative of expression injection attacks.
*   Implement input validation and sanitization measures to prevent malicious expressions from reaching the math.js parser.
