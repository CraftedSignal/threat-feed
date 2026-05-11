---
title: '@theecryptochad/merge-guard Prototype Pollution Vulnerability'
slug: 2026-05-merge-guard-prototype-pollution
description: '`@theecryptochad/merge-guard` versions prior to 1.0.1 are vulnerable to Prototype Pollution via the `deepMerge()` function, allowing an attacker who controls the source object to inject `__proto__` keys that mutate `Object.prototype`, affecting all objects in the Node.js runtime.'
date: "2026-05-11T16:10:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - javascript
  - node.js
vendors:
  - TheeCryptoChad
products:
  - '@theecryptochad/merge-guard (< 1.0.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-mhwj-73qx-jqxm
  - https://cwe.mitre.org/data/definitions/1321.html
  - https://owasp.org/www-community/attacks/Prototype_Pollution
  - https://github.com/TheeCryptoChad/merge-guard/releases/tag/v1.0.1
rules:
  - title: Detect Prototype Pollution via deepMerge
    description: Detects HTTP requests attempting to exploit Prototype Pollution in deepMerge functions by searching for __proto__ in request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect deepMerge with user-controlled input
    description: Detects usage of deepMerge function calls with user-controlled input as a parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `@theecryptochad/merge-guard` npm package, specifically versions prior to 1.0.1, contains a prototype pollution vulnerability in its `deepMerge()` function. This vulnerability arises from the lack of sanitization of reserved property keys like `__proto__` during the recursive merging of objects. If an attacker can control the contents of the source object passed to `deepMerge()`, they can inject `__proto__` properties that modify the base `Object.prototype`. This pollution affects all objects within the Node.js runtime, potentially leading to privilege escalation, application logic bypass, or other unexpected behavior. Successful exploitation requires the application to use `deepMerge()` with user-controlled input.

## Attack Chain

1. The application receives untrusted data from an external source (e.g., HTTP request, WebSocket message, config file).
2. The untrusted data is parsed as a JSON object.
3. The attacker crafts the JSON object to include a `__proto__` property with a malicious payload as its value. For example: `{"__proto__": {"isAdmin": true}}`.
4. The `deepMerge()` function is called with a target object and the attacker-controlled JSON object as the source.
5. Due to the missing sanitization, the `__proto__` property in the source object overwrites the `Object.prototype` with the malicious payload.
6. Subsequently, all objects in the Node.js runtime inherit the injected properties (e.g., `isAdmin: true`).
7. The attacker leverages the polluted `Object.prototype` to bypass application logic or escalate privileges.
8. The application's behavior is altered, potentially leading to data breaches, unauthorized access, or other security impacts.

## Impact

Applications using vulnerable versions of `@theecryptochad/merge-guard` and passing unsanitized user-supplied data to the `deepMerge()` function are at risk. An attacker can inject arbitrary properties onto `Object.prototype`, leading to privilege escalation and application logic bypass. The number of affected applications is currently unknown, but the risk is significant for applications that process untrusted input. A successful attack allows the attacker to modify the behavior of the entire Node.js application.

## Recommendation

*   Upgrade to `@theecryptochad/merge-guard >= 1.0.1` to remediate the vulnerability. This version adds a blocklist to prevent modification of `__proto__`, `constructor`, and `prototype` properties (see Remediation section in Content).
*   Deploy the Sigma rule "Detect Prototype Pollution via deepMerge" to detect attempts to exploit this vulnerability via HTTP requests containing `__proto__` keys (see Rules).
*   Sanitize all user-supplied data before passing it to `deepMerge()` to prevent the injection of malicious properties.
