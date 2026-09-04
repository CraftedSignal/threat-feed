---
title: Prototype Pollution in toml Node.js Package via Path Desynchronization
slug: 2026-09-toml-prototype-pollution
description: The toml Node.js package contains a prototype pollution vulnerability (CVE-2026-63376) that allows attackers to corrupt Object.prototype via __proto__ path manipulation and path-format desynchronization, potentially leading to RCE.
date: "2026-09-04T00:05:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:toml_project:toml:*:*:*:*:*:node.js:*:*
tags:
  - prototype-pollution
  - supply-chain
  - nodejs
products:
  - toml (< 4.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The compiler flaw allows an attacker to write arbitrary properties onto Object.prototype, which enables logic and authorization bypass and remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-63376
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-v5mp-jgw5-2x6j
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade all instances of the toml dependency to version 4.1.2 or later
      owner: Application Security
      due: 24h
      evidence: Source advisory recommends version 4.1.2 for CVE-2026-63376
  mitigation_plan:
    - priority: immediate
      action: Upgrade to toml 4.1.2
      owner: IT Operations
      addresses: CVE-2026-63376
      evidence: Source advisory
---

The `toml` Node.js package (vulnerable versions < 4.1.2) is susceptible to a high-severity prototype pollution vulnerability, tracked as CVE-2026-63376. The vulnerability stems from two primary failures in the package's compiler logic: the lack of reserved key validation during path traversal and a path-format desynchronization between internal tracking sets.

The compiler resolves paths using `deepRef`, which treats `__proto__` as an ordinary key. Because intermediate tables are created with `Object.create(null)` but assigned values are not, an attacker can traverse through a scalar value (e.g., a number) into the prototype chain of that scalar's constructor, eventually reaching `Object.prototype`. Furthermore, the internal protection mechanism intended to block path redefinition fails because the tracking strings and the actual traversal path strings utilize different formats - comma-joined versus dot-joined - causing the guard condition to miss. An attacker providing a malicious TOML file can inject arbitrary properties into `Object.prototype`, affecting all objects within the Node.js process. This vulnerability is critical for any application using `toml` to parse external, untrusted input.

## Attack Chain

1. Attacker crafts a malicious TOML payload containing a nested path that targets `__proto__`.
2. The payload defines a scalar value at a path (e.g., `a.b.y = 1`) to occupy a location in the object graph.
3. The attacker introduces a subsequent table definition targeting `a.b.y.__proto__.__proto__`.
4. The `toml` parser's `deepRef` function begins traversal of the malicious key path.
5. The internal path-format desynchronization causes the redefinition guard to fail, as the stored path `"a,b.y"` does not match the dot-delimited lookup path `"a.b.y"`.
6. The parser traverses the prototype chain of the scalar value at `a.b.y`, landing on `Object.prototype`.
7. The parser writes the attacker's desired property onto `Object.prototype`.
8. The application performs a logic check or gadget execution that references a polluted property, resulting in RCE or authorization bypass.

## Impact

Successful exploitation allows for the modification of the global `Object.prototype` within the target Node.js process. This results in global state corruption, which can be leveraged for denial of service, privilege escalation, or remote code execution if the application environment contains reachable gadgets. Given the widespread use of the `toml` package (14.8 million weekly downloads), this poses a systemic risk to dependent configuration loaders and application front-matter parsers.

## Recommendation

1. Upgrade the `toml` dependency to version 4.1.2 or later immediately to patch CVE-2026-63376.
2. Audit applications using `toml.parse()` that process untrusted inputs, such as configuration files, project manifests, or user-supplied TOML strings.
3. Use static analysis tools to identify if user-controlled input flows into `toml.parse()`.
