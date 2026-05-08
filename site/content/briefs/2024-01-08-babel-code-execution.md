---
title: Babel Plugin Vulnerability Leads to Arbitrary Code Execution via Malicious Input
slug: 2024-01-08-babel-code-execution
description: 'A maliciously crafted input to Babel''s `@babel/plugin-transform-modules-systemjs` or `@babel/preset-env` with `modules: ''systemjs''` can cause the tool to generate arbitrary code execution.'
date: "2026-05-08T20:34:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - code-generation
  - arbitrary-code-execution
  - babel
vendors:
  - Babel
products:
  - '@babel/plugin-transform-modules-systemjs'
  - '@babel/preset-env'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/advisories/GHSA-fv7c-fp4j-7gwp
rules:
  - title: Detect CVE-2026-44728 Babel Code Generation Vulnerability
    description: Detects CVE-2026-44728 exploitation — Monitors process execution involving Babel that might be triggered by processing a malicious input file
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-44728 Babel Code Generation Vulnerability - Preset Env
    description: Detects CVE-2026-44728 exploitation — Monitors process execution involving Babel using the preset-env with the vulnerable systemjs modules option
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A vulnerability exists in Babel's `@babel/plugin-transform-modules-systemjs` plugin and `@babel/preset-env` when configured with the `modules: "systemjs"` option. An attacker can supply a specially crafted input to Babel, causing the tool to generate malicious output code that results in arbitrary code execution when processed. This vulnerability impacts versions of `@babel/plugin-transform-modules-systemjs` between 7.12.0 and 7.29.3, as well as versions between 8.0.0-alpha.0 and 8.0.0-alpha.12. The `@babel/preset-env` is vulnerable when it uses the vulnerable `@babel/plugin-transform-modules-systemjs`. This vulnerability, reported by Daniel Cervera, does not affect users who only compile trusted code, meaning developers who compile user-submitted code are at higher risk.

## Attack Chain

1.  Attacker crafts a malicious JavaScript input file designed to exploit the code generation flaw in Babel.
2.  The attacker provides the malicious JavaScript file to a vulnerable Babel instance for compilation. This could occur through various means, such as a build process.
3.  Babel, using either `@babel/plugin-transform-modules-systemjs` or `@babel/preset-env` with the `modules: "systemjs"` option, processes the malicious input file.
4.  Due to the vulnerability, Babel generates a malicious JavaScript output file containing attacker-controlled code.
5.  The generated malicious JavaScript file is then included in a web application or other JavaScript runtime environment.
6.  A user or process executes the malicious JavaScript code.
7.  The attacker-controlled code executes arbitrary commands on the system or within the application's context.
8.  The attacker gains unauthorized access, modifies data, or disrupts services, depending on the permissions available to the executed code.

## Impact

Successful exploitation allows an attacker to execute arbitrary code in the context of the Babel process. This can lead to a variety of impacts, including but not limited to, unauthorized access to sensitive data, modification of application code, or complete system compromise, depending on where and how the compiled code is used. The severity is high because it can potentially give an attacker complete control over the system if the compiled output is run in a privileged environment.

## Recommendation

*   Upgrade `@babel/plugin-transform-modules-systemjs` to version 7.29.4 or later. If using `@babel/preset-env`, upgrade to version 7.29.5 to pull in the updated `@babel/plugin-transform-modules-systemjs` dependency.
*   Apply the provided Sigma rule `Detect CVE-2026-44728 Babel Code Generation Vulnerability` to identify potential exploitation attempts based on process execution with Babel.
*   Consider migrating away from the `modules: "systemjs"` option to native ES Modules or other module formats to avoid this type of vulnerability.
*   If immediate patching is not possible, and you're working with a legacy codebase, consider pinning `@babel/parser` to v7.11.5, however, be aware of the potential impact on other language features.
