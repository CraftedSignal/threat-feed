---
title: protobuf.js Prototype Pollution Leads to Code Generation Gadget
slug: 2026-05-protobufjs-prototype-pollution
description: protobufjs versions 7.5.5 and earlier, as well as versions 8.0.0 through 8.0.1, are vulnerable to arbitrary JavaScript execution if Object.prototype has been polluted, allowing attackers to influence generated encode/decode functions.
date: "2026-05-12T15:02:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - code-generation
  - javascript
vendors:
  - npm
products:
  - protobufjs (<= 7.5.5)
  - protobufjs (>= 8.0.0, <= 8.0.1)
references:
  - https://github.com/advisories/GHSA-75px-5xx7-5xc7
  - CVE-2026-44291
rules:
  - title: Detect Prototype Pollution Attempts via Object.prototype Modification
    description: Detects attempts to modify Object.prototype, a common prerequisite for prototype pollution attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Creation with Suspicious Access to Object Prototype
    description: Detects processes that may be attempting to leverage prototype pollution by modifying Object.prototype followed by potentially malicious process creation.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The protobuf.js library, a JavaScript implementation of Protocol Buffers, is susceptible to a code generation gadget vulnerability (CVE-2026-44291). Specifically, versions 7.5.5 and earlier, as well as versions 8.0.0 through 8.0.1, utilize plain objects with inherited prototypes for internal type lookup tables. If an attacker can first pollute the `Object.prototype`, they can inject attacker-controlled strings into generated JavaScript code via protobufjs encode or decode functions. This occurs because the lookup tables can resolve attacker-controlled inherited properties as valid protobuf type information. Exploitation necessitates a separate prototype pollution primitive and requires the application to use protobufjs functionality that generates code for affected types. This issue poses a significant risk in environments where untrusted input can influence the `Object.prototype`.

## Attack Chain

1. An attacker identifies a prototype pollution vulnerability within the application or one of its dependencies.
2. The attacker leverages the prototype pollution vulnerability to inject malicious properties into `Object.prototype`.
3. The injected properties are crafted to influence protobufjs's internal type lookup tables.
4. The application invokes protobufjs functionality to generate encode or decode functions for protobuf messages.
5. Due to the prototype pollution, the generated code includes attacker-controlled strings, leading to unexpected behavior.
6. The generated code is executed within the application's context.
7. The attacker-controlled strings in the generated code are interpreted as JavaScript code.
8. This leads to arbitrary JavaScript execution within the application, potentially allowing the attacker to compromise the system.

## Impact

Successful exploitation allows attackers to achieve arbitrary JavaScript execution within the context of the affected application. This could lead to complete compromise of the application and potentially the underlying system. The severity of the impact is high, as it allows for remote code execution (RCE). There is no information about specific victim counts or sectors targeted available at this time.

## Recommendation

- Upgrade protobufjs to a patched version (later than 7.5.5 or 8.0.1) to remediate CVE-2026-44291.
- Review and mitigate any potential prototype pollution vulnerabilities in your application or its dependencies as mentioned in the overview.
- Deploy the Sigma rule "Detect Prototype Pollution Attempts via Object.prototype Modification" to identify potential prototype pollution attacks targeting `Object.prototype`.
- If immediate upgrade is not possible, isolate schema/message processing from untrusted application state.
