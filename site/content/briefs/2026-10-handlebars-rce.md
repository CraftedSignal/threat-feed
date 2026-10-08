---
title: Handlebars Prototype Pollution and RCE via Function Constructor Bypass
slug: 2026-10-handlebars-rce
description: Handlebars (v4.0.0-4.7.9) is vulnerable to a prototype-access deny list bypass where own property checks permit the retrieval of the Function constructor, enabling remote code execution when allowProtoMethodsByDefault is enabled.
date: "2026-10-08T19:25:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - prototype-pollution
  - javascript-injection
products:
  - handlebars (v4.0.0 to v4.7.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker uses Function to create a function with attacker-controlled body content and triggers its execution through Handlebars template rendering mechanics.
    confidence_band: high
cves:
  - id: CVE-2026-106445
    epss: 0.00411
references:
  - https://github.com/advisories/GHSA-p8wg-vrv2-v86f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106445
action_plan:
  priority: immediate_escalation
  owners:
    - Application Security
    - DevOps
  immediate_actions:
    - action: Disable allowProtoMethodsByDefault in all Handlebars template configurations
      owner: DevOps
      due: 24h
      evidence: Source workaround guidance
  mitigation_plan:
    - priority: immediate
      action: Upgrade handlebars to 4.7.10 or later
      owner: IT Operations
      addresses: CVE-2026-106445
      evidence: Source security advisory
---

Handlebars (v4.0.0 through v4.7.9) contains a critical vulnerability (CVE-2026-106445) involving the mishandling of prototype properties. The library's `lookupProperty` function incorrectly trusts properties identified as "own" properties, effectively bypassing the security deny list designed to block access to dangerous methods like `constructor`. In environments where `allowProtoMethodsByDefault` is set to `true` when compiling templates, an attacker capable of providing a Handlebars template can navigate the prototype chain to reach `Function.prototype`. Because the `constructor` property is an own property of prototype objects, the engine returns it without evaluating the deny list. This grants the attacker access to the JavaScript `Function` constructor, which can then be leveraged to create and execute arbitrary code on the server-side runtime.

## Attack Chain

1. Attacker identifies a target application rendering Handlebars templates where `allowProtoMethodsByDefault` is configured as `true`.
2. Attacker submits a malicious Handlebars template string to the application's template rendering engine.
3. Attacker uses `{{lookup myFunction "__proto__"}}` or similar expressions to navigate to `Function.prototype`.
4. Attacker invokes `{{lookup (lookup myFunction "__proto__") "constructor"}}`, exploiting the `hasOwnProperty` trust in `lookupProperty` to retrieve the `Function` object.
5. Attacker pushes the `Function` object into an array accessible within the template context via `{{lookup "" (@root.a.push ...)}}`.
6. Attacker uses Handlebars helper directives (e.g., `#each` or `#with`) to invoke the retrieved `Function` constructor.
7. The `Function` constructor evaluates an attacker-supplied string as JavaScript, leading to Remote Code Execution (RCE) in the Node.js runtime.

## Impact

Successful exploitation leads to full Remote Code Execution (RCE) on the server running the Node.js application. This allows an attacker to execute arbitrary system commands, potentially resulting in data exfiltration, service disruption, or further compromise of the host infrastructure. The vulnerability affects all versions of Handlebars between 4.0.0 and 4.7.9.

## Recommendation

* Immediately identify all application codebases utilizing Handlebars where the `allowProtoMethodsByDefault` option is set to `true`.
* Set `allowProtoMethodsByDefault` to `false` in all template compilation configurations until the environment can be patched or verified as secure.
* Upgrade the Handlebars dependency to a version where CVE-2026-106445 is remediated.
* Implement strict server-side validation and sanitization for any user-supplied strings that are subsequently rendered by the Handlebars template engine.
