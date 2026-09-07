---
title: Handlebars.js Remote Code Execution via AST Injection
slug: 2024-01-16-handlebars-rce
description: Handlebars.js versions 4.0.0 through 4.7.8 are vulnerable to remote code execution via a crafted AST that injects arbitrary JavaScript through the `Handlebars.compile()` function.
date: "2024-01-16T14:30:00Z"
lastmod: "2026-09-07T21:43:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-C0GNIT00-CVE-2026-33937&utm_source=rss&utm_medium=rss
tags:
  - handlebars
  - rce
  - ast-injection
  - javascript
vendors:
  - Handlebarsjs
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-33937
    cvss: 9.8
    epss: 0.01704
references:
  - https://github.com/advisories/GHSA-2w6w-674q-4c4q
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-C0GNIT00-CVE-2026-33937&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Handlebars.js AST Injection via NumberLiteral Value
    description: Detects suspicious process execution originating from Node.js processes after a Handlebars.js template compilation, indicative of AST injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Handlebars.js AST Injection - process.getBuiltinModule usage
    description: Detects the usage of process.getBuiltinModule('child_process') within javascript, which can lead to code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-09-07T21:43:41Z"
    level: L2
    summary: poc_available; added CVE-2026-33937
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-C0GNIT00-CVE-2026-33937&utm_source=rss&utm_medium=rss
---

Handlebars.js is vulnerable to remote code execution (RCE) due to insufficient sanitization when handling Abstract Syntax Trees (ASTs). Specifically, the `Handlebars.compile()` function in versions 4.0.0 through 4.7.8 directly emits the `value` field of a `NumberLiteral` AST node into the generated JavaScript without proper escaping or sanitization. This allows an attacker who can control the input to `Handlebars.compile()` to inject arbitrary JavaScript code, leading to RCE on the server. The vulnerability, identified as CVE-2026-33937, arises when `Handlebars.compile()` receives a pre-parsed AST object instead of a template string. This is particularly dangerous in scenarios where user-supplied JSON is deserialized and directly passed to `Handlebars.compile()`.

## Attack Chain

1.  The attacker identifies a server-side application that uses Handlebars.js for templating and deserializes JSON from user input, such as an Express application using `express.json()`.
2.  The attacker crafts a malicious JSON payload containing a `NumberLiteral` AST node with a `value` field designed to execute arbitrary JavaScript.
3.  The malicious JSON payload is sent to an endpoint that passes the deserialized JSON directly to `Handlebars.compile()`.
4.  `Handlebars.compile()` processes the AST and, due to the vulnerability, includes the attacker-controlled `value` from the `NumberLiteral` node verbatim into the generated JavaScript code.
5.  The generated JavaScript code is then evaluated, typically using `eval()` or a similar function.
6.  The injected JavaScript code executes arbitrary commands on the server, such as using `process.getBuiltinModule('child_process').execFileSync()` to run system commands.
7.  The output of the executed commands is returned to the attacker, confirming successful RCE.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the server hosting the vulnerable Handlebars.js application. This can lead to complete compromise of the server, including data theft, system takeover, and denial of service. The vulnerability affects applications using Handlebars.js versions 4.0.0 through 4.7.8. The provided proof-of-concept demonstrates the execution of the `id` command, highlighting the potential for more severe attacks.

## Recommendation

*   Implement input validation to ensure that the argument passed to `Handlebars.compile()` is always a string and not a JSON-deserialized object, as demonstrated in the workaround example.
*   Apply the workaround of using the Handlebars runtime-only build (`handlebars/runtime`) on the server if templates are pre-compiled at build time to remove the `compile()` function.
*   Upgrade Handlebars.js to a version outside the vulnerable range (>= 4.0.0, <= 4.7.8) to patch CVE-2026-33937.
