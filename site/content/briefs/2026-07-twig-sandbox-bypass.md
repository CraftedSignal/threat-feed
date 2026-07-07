---
title: 'Twig: Sandbox filter, tag and function allow-list bypass when sandbox state changes between renders for a cached `Template`'
slug: 2026-07-twig-sandbox-bypass
description: A high-severity vulnerability, CVE-2026-49981, in the Twig templating engine allows for a sandbox bypass when the sandbox state changes between renders for a cached `Template` instance, enabling the execution of otherwise restricted filters, tags, and functions in sandboxed contexts.
date: "2026-07-03T12:40:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - twig
  - vulnerability
  - sandbox-bypass
  - web-application
  - rce
vendors:
  - Twig Project
products:
  - Twig (<= 3.26.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker identifies a web application feature that allows the submission or modification of Twig templates.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malicious template then executes functions or uses filters/tags that would normally be blocked by the sandbox, leading to arbitrary code execution on the server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-529h-vh3j-85hq
---

A critical vulnerability (CVE-2026-49981) has been identified in the Twig templating engine, specifically affecting versions up to 3.26.0. This flaw allows an attacker to bypass the security sandbox's filter, tag, and function allow-lists in applications utilizing long-lived worker environments (e.g., FrankenPHP, RoadRunner, Symfony Messenger consumers). The core issue stems from the `checkSecurity()` method, which governs template security, being invoked only once during a template's initial construction and caching. If the application later changes its sandbox state—such as enabling or disabling the sandbox, or altering the security policy—a previously cached `Template` instance retains its initial, potentially less restrictive, security verdict. This oversight allows an attacker to execute arbitrary code or functions that should be prohibited within a sandboxed environment, presenting a significant risk for server-side template injection leading to remote code execution.

## Attack Chain

1.  **Initial Access / Malicious Template Injection**: An attacker identifies a web application feature that allows the submission or modification of Twig templates, such as a custom theme editor, report generator, or CMS, typically achieved via an exploit in another component or a legitimate feature misused.
2.  **Non-Sandboxed Pre-Rendering**: The attacker crafts a malicious Twig template and arranges for the vulnerable application to render it (or a part of it, like a shared layout) in an initially *non-sandboxed* context.
3.  **Template Caching with Permissive Verdict**: Twig processes this non-sandboxed template, creating and caching a `Template` instance. The built-in `checkSecurity()` method is invoked, recording a permissive security verdict due to the non-sandboxed environment.
4.  **Sandbox State Transition**: The application's environment later transitions to a *sandboxed* state, either through `enableSandbox()`/`disableSandbox()` calls or a change in the `SecurityPolicy` for subsequent template renders.
5.  **Cached Template Reuse**: The application attempts to render the *same previously cached `Template` instance* (e.g., through an `extends`, `use`, `include`, or `import` statement) in this now-sandboxed context.
6.  **Security Policy Bypass**: Due to the vulnerability, the cached `Template` instance reuses its initial, permissive security verdict for filters, tags, and functions, effectively bypassing the newly active sandbox `SecurityPolicy`.
7.  **Arbitrary Code Execution**: The malicious template then executes functions or uses filters/tags that would normally be blocked by the sandbox, leading to arbitrary code execution on the server.
8.  **Impact**: Successful exploitation allows for remote code execution, data exfiltration, and potential full system compromise.

## Impact

This vulnerability poses a significant risk to web applications using Twig in environments where the sandbox state can change dynamically, particularly in long-lived workers like those found in FrankenPHP, RoadRunner, or Symfony Messenger consumers. A successful exploitation of CVE-2026-49981 can lead to arbitrary code execution on the affected server, enabling attackers to fully compromise the host system, exfiltrate sensitive data, or install further malicious software. While specific victim counts are not available, Twig is a widely used templating engine across various PHP applications, making many organizations potentially susceptible if their deployments meet the vulnerable configuration.

## Recommendation

*   **Patch CVE-2026-49981 immediately** by upgrading `composer/twig/twig` to a version greater than 3.26.0. This addresses the core vulnerability.
*   **Review your application's Twig usage** to ensure `Environment` instances are properly isolated and not shared between sandboxed and non-sandboxed contexts, especially in long-lived worker processes, as described in this brief.
