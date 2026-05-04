---
title: Thymeleaf Server-Side Template Injection Vulnerability
slug: 2024-01-03-thymeleaf-ssti
description: A server-side template injection vulnerability exists in Thymeleaf versions up to 3.1.4.RELEASE due to improper neutralization of specific constructs, allowing the execution of potentially dangerous expressions in sandboxed contexts if unsanitized variables are passed to the template engine.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssti
  - template-injection
  - thymeleaf
  - cve-2026-41901
vendors:
  - org.thymeleaf
products:
  - thymeleaf (<= 3.1.4.RELEASE)
  - thymeleaf-spring5 (<= 3.1.4.RELEASE)
  - thymeleaf-spring6 (<= 3.1.4.RELEASE)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://github.com/advisories/GHSA-c9ph-gxww-7744
rules:
  - title: Detect Suspicious Thymeleaf Template Injection Attempts
    description: Detects potential Server-Side Template Injection (SSTI) attempts in Thymeleaf applications by identifying suspicious patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Thymeleaf POST Template Injection Attempts
    description: Detects potential Server-Side Template Injection (SSTI) attempts in Thymeleaf applications via POST requests.
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

A critical security vulnerability, CVE-2026-41901, has been identified in Thymeleaf, a Java template engine, affecting versions up to and including 3.1.4.RELEASE. This vulnerability allows for Server-Side Template Injection (SSTI) due to the improper neutralization of specific syntax patterns within sandboxed expression execution. Specifically, the library fails to properly sanitize certain constructs, allowing potentially dangerous expressions to be executed even within supposedly restricted contexts. This poses a significant risk if application developers pass unsanitized variables to the template engine and these variables are then utilized in sandboxed areas within the templates. Successful exploitation can lead to arbitrary code execution on the server. All users of affected versions are strongly advised to upgrade to version 3.1.5.RELEASE as soon as possible.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of Thymeleaf (<= 3.1.4.RELEASE).
2. The attacker locates a template within the application that uses Thymeleaf's expression evaluation within a sandboxed context.
3. The attacker identifies an input field or parameter that passes data to the Thymeleaf template engine.
4. The attacker crafts a malicious payload containing a Thymeleaf expression designed to bypass the sandbox restrictions. This payload may utilize specific syntax patterns not properly neutralized by the vulnerable Thymeleaf version.
5. The attacker injects the crafted payload into the identified input field.
6. The application processes the attacker-controlled input via the Thymeleaf template engine.
7. Due to the vulnerability, the malicious Thymeleaf expression is executed despite the intended sandboxing.
8. The attacker achieves arbitrary code execution on the server, potentially gaining full control of the system.

## Impact

Successful exploitation of CVE-2026-41901 can lead to complete system compromise. An attacker could potentially execute arbitrary code, install malware, steal sensitive data, or disrupt application services. The vulnerability affects any application using Thymeleaf versions up to 3.1.4.RELEASE, potentially impacting numerous organizations across various sectors. The lack of proper input sanitization is the root cause, which can be difficult to identify and mitigate without patching the underlying Thymeleaf library.

## Recommendation

*   Immediately upgrade Thymeleaf to version 3.1.5.RELEASE or later to patch CVE-2026-41901.
*   If immediate patching is not feasible, review and sanitize all data passed to the Thymeleaf template engine to prevent the injection of malicious expressions. However, this workaround is not a complete solution and upgrading is strongly recommended.
*   Deploy the Sigma rule "Detect Suspicious Thymeleaf Template Injection Attempts" to identify potential exploitation attempts in web server logs, focusing on HTTP requests containing suspicious patterns related to Thymeleaf expressions.
*   Enable verbose logging on your web servers to capture detailed information about HTTP requests and responses, which can aid in identifying and investigating potential template injection attacks.
