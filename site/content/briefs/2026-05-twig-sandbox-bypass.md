---
title: Twig Sandbox Bypass via Object Destructuring Assignment (CVE-2026-46639)
slug: 2026-05-twig-sandbox-bypass
description: A vulnerability in Twig versions 3.24.0 to 3.26.0 (CVE-2026-46639) allows an attacker with write access to a sandboxed Twig template to bypass security policy restrictions by exploiting object-destructuring assignment to read any public property or invoke any public getter on objects passed to the template engine.
date: "2026-05-21T21:32:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - twig
  - sandbox-bypass
  - cve-2026-46639
vendors:
  - Twig
products:
  - twig/twig (>= 3.24.0, < 3.26.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-mm6w-gr99-p3jj
  - CVE-2026-46639
rules:
  - title: Detect Twig Sandbox Bypass via getAttribute
    description: Detects CVE-2026-46639 exploitation — Calls to `CoreExtension::getAttribute` with the `$sandboxed` argument set to `false`, indicating a potential sandbox bypass.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

Twig versions 3.24.0 to 3.26.0 contain a sandbox bypass vulnerability (CVE-2026-46639) due to the object-destructuring assignment syntax introduced in version 3.24.0. This syntax generates a call to `CoreExtension::getAttribute()` with the `$sandboxed` argument hardcoded to `false`, effectively disabling property and method policy checks. An attacker with write access to a sandboxed Twig template can exploit this to read any public property or invoke any public getter on objects passed to the template engine, bypassing the intended `SecurityPolicy` restrictions. The exploit requires only the `{% do %}` tag to be in `allowedTags`, a common configuration in many Twig deployments. This bypass allows attackers to potentially gain sensitive information or execute arbitrary code depending on the objects passed to the template.

## Attack Chain

1. An attacker gains write access to a Twig template file within a sandboxed environment.
2. The attacker injects a Twig template containing an object-destructuring assignment expression, such as `{% set { foo, bar } = my_object %}`.
3. The Twig template engine parses and compiles the modified template.
4. During compilation, the `ObjectDestructuringSetBinary::compile()` function is invoked.
5. `ObjectDestructuringSetBinary::compile()` generates a call to `CoreExtension::getAttribute()` with the `$sandboxed` argument set to `false`.
6. When the template is rendered, the `getAttribute()` function is executed without enforcing the sandbox's property and method access restrictions.
7. The attacker is able to read public properties and invoke public getters of `my_object` that would normally be blocked by the `SecurityPolicy`.
8. The attacker leverages the ability to access sensitive data or trigger unintended behavior, potentially escalating privileges or gaining further access to the system.

## Impact

Successful exploitation of this vulnerability (CVE-2026-46639) allows attackers to bypass the Twig sandbox, potentially leading to information disclosure or arbitrary code execution. The number of affected installations is unknown, but any Twig application using versions 3.24.0 to 3.26.0 with a sandboxed environment is vulnerable if an attacker can modify the template files. The primary impact is a loss of confidentiality and integrity within the application, as attackers can access sensitive data or modify application behavior.

## Recommendation

*   Upgrade to Twig version 3.26.0 or later to patch CVE-2026-46639.
*   Implement strict access controls to prevent unauthorized modification of Twig template files.
*   Deploy the Sigma rule `Detect Twig Sandbox Bypass via getAttribute` to detect exploitation attempts based on the vulnerable `getAttribute()` calls.
