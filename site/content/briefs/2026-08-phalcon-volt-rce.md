---
title: Phalcon Volt Compiler SSTI to RCE via join Filter
slug: 2026-08-phalcon-volt-rce
description: The Phalcon Volt template compiler fails to escape arguments in the join filter, allowing unauthenticated attackers to perform server-side template injection leading to remote code execution (CVE-2026-59989).
date: "2026-08-22T01:16:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Phalcon
products:
  - cphalcon (<= 5.15.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The injected PHP code executes i.e. compile-time PHP code injection (server-side template injection -> remote code execution).
    confidence_band: high
cves:
  - id: CVE-2026-59989
references:
  - https://github.com/advisories/GHSA-hrwp-4hh9-c8r8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59989
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update cphalcon to version 5.15.1 or later to address CVE-2026-59989.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-59989 vulnerability details
  mitigation_plan:
    - priority: immediate
      action: Identify and sanitize any input passed to Phalcon Volt compilers.
      owner: Development
      addresses: CVE-2026-59989
      evidence: PoC demonstrates injection via join filter arguments
---

The Volt template compiler in Phalcon (cphalcon <= 5.15.0) contains a critical vulnerability (CVE-2026-59989) in the implementation of the `join` filter. During the compilation of Volt templates into PHP, the compiler performs direct string concatenation of raw template arguments into the generated PHP code without any escaping or neutralization. Specifically, the separator literal and the array argument are spliced verbatim into the generated `join('…', …)` call.

An attacker who can provide input to the Volt template rendering engine can inject arbitrary PHP instructions by breaking out of the intended function syntax. Because Phalcon writes these compiled templates to cache files and executes them via `require()` at render time, the injected PHP code is executed within the context of the web-server process. This allows for full remote code execution on any application utilizing an affected version of Phalcon that permits user-influenced Volt templates.

## Attack Chain

1. Attacker identifies a web application utilizing Phalcon Volt where template content or specific filter arguments are influenced by user input.
2. Attacker crafts a malicious Volt template string containing a `join` filter call.
3. Attacker injects a payload into the `join` separator or array argument, such as `"',[]); echo shell_exec('id'); //"`.
4. The Phalcon `Compiler` processes the template, concatenating the malicious input verbatim into the generated PHP cache file.
5. The resulting PHP file is written to the application's cache directory with the injected payload placed inside a `join()` function call.
6. The application calls the Volt rendering engine for the template.
7. The engine executes `require()` on the malicious cache file.
8. The injected payload executes, granting the attacker arbitrary code execution on the server.

## Impact

Successful exploitation results in full remote code execution in the context of the web-server process. This impact is applicable to all applications using Phalcon cphalcon versions up to and including 5.15.0 where template input can be manipulated by an attacker.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

* Patch Phalcon cphalcon to a version after 5.15.0 to resolve CVE-2026-59989.
* Audit application code for instances where user-supplied data is passed directly into template engine rendering functions or Volt template string compilation.
* Deploy webserver logs to monitor for suspicious input in parameters that could be interpreted as template arguments.
* Implement input validation on all template-related inputs to prevent injection of template control characters or syntax breaking sequences.
