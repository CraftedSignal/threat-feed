---
title: Server-Side Template Injection to Remote Code Execution in @prompty/core Nunjucks Renderer
slug: 2026-07-prompty-ssti-rce
description: A critical server-side template injection vulnerability exists in the @prompty/core Nunjucks renderer, affecting versions <= 0.1.4 and >= 2.0.0-alpha.1 up to <= 2.0.0-beta.4. This flaw allows an attacker to execute arbitrary JavaScript code within the host Node.js process by crafting malicious `.prompty` template bodies. The renderer's unrestricted JavaScript member access permits traversal of constructor and prototype properties, leading to remote code execution when rendering untrusted, community-supplied, cloned, or LLM-generated `.prompty` files.
date: "2026-07-24T16:30:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - server-side-template-injection
  - remote-code-execution
  - nodejs
  - npm
  - vulnerability
vendors:
  - prompty
products:
  - '@prompty/core (<= 0.1.4)'
  - '@prompty/core (>= 2.0.0-alpha.1, <= 2.0.0-beta.4)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker-controlled template could traverse constructor and prototype properties to execute JavaScript in the host Node.js process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w28w-gp39-m4p6
---

A critical server-side template injection (SSTI) vulnerability, tracked as GHSA-w28w-gp39-m4p6, has been identified in the `@prompty/core` Nunjucks renderer library for Node.js applications. This vulnerability impacts versions `<= 0.1.4` and `2.0.0-alpha.1` up to `<= 2.0.0-beta.4`. The flaw stems from the renderer's evaluation of untrusted `.prompty` template bodies with unrestricted JavaScript member access. Attackers can exploit this by crafting malicious template content that traverses constructor and prototype properties, enabling arbitrary JavaScript code execution within the host Node.js process. This poses a significant risk to applications that process or render untrusted, community-supplied, cloned, or Large Language Model (LLM)-generated `.prompty` files, as it can lead to full remote code execution with the privileges of the underlying Node.js application.

## Attack Chain

1. An attacker crafts a malicious `.prompty` template body containing Nunjucks SSTI payloads designed to exploit JavaScript member access.
2. The attacker delivers this malicious template to a vulnerable application using the `@prompty/core` renderer.
3. The vulnerable application ingests and attempts to render the untrusted `.prompty` file.
4. During rendering, the `@prompty/core` Nunjucks renderer evaluates the template body, which includes the attacker's payload.
5. Due to unrestricted JavaScript member access, the payload successfully traverses constructor and prototype properties of JavaScript objects within the Node.js runtime.
6. This traversal allows the attacker to execute arbitrary JavaScript code within the context of the host Node.js process.
7. Remote Code Execution (RCE) is achieved, giving the attacker control over the server with the application's privileges.

## Impact

Applications that utilize the `@prompty/core` library and render untrusted `.prompty` files are at severe risk. A successful exploitation of this critical vulnerability leads to remote code execution (RCE) on the server. Attackers can leverage this access to steal sensitive data, deploy further malware, establish persistence, or completely compromise the affected system. The impact extends to any data managed by the Node.js application and the underlying operating system. The vulnerability's severity is critical due to the direct path from untrusted input to arbitrary code execution, potentially affecting a broad range of applications that integrate with external template sources, such as those involving user-generated content or LLM integrations.

## Recommendation

* Upgrade all instances of `@prompty/core` to version `2.0.0-beta.5` or later immediately to apply the security patch. The patched renderer sanitizes render inputs, rejects constructor/prototype member traversal, and disallows template function calls, while maintaining support for ordinary interpolation, conditionals, loops, and own nested data properties.
