---
title: Prototype Pollution Vulnerability in @nevware21/ts-utils Library (CVE-2026-46681)
slug: 2026-05-ts-utils-prototype-pollution
description: The `_copyProps` function in the `@nevware21/ts-utils` library is vulnerable to prototype pollution due to the use of `for...in` without proper `hasOwnProperty` checks, allowing attackers to modify object prototypes by injecting properties like `__proto__`.
date: "2026-05-21T21:44:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - javascript
  - vulnerability
  - cve-2026-46681
vendors:
  - nevware21
products:
  - '@nevware21/ts-utils'
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-x7j8-49r8-mr43
  - CVE-2026-46681
rules:
  - title: Detect Prototype Pollution via __proto__ Modification
    description: Detects prototype pollution attempts by monitoring for registry modifications targeting the __proto__ property.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - registry_set
      - windows
  - title: Detect Prototype Pollution via JSON Parsing
    description: Detects prototype pollution attempts by monitoring process creation events where a script parses a JSON object containing __proto__.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `@nevware21/ts-utils` library, versions 0.13.0 and earlier, contains a prototype pollution vulnerability (CVE-2026-46681) in the `_copyProps` function located in `lib/src/object/copy.ts`. This function iterates through the properties of a source object using a `for...in` loop without checking if the properties belong directly to the object (i.e., without using `hasOwnProperty`). Consequently, an attacker can inject malicious properties, such as `__proto__`, into the prototype chain of all objects within the application. By providing crafted JSON input with a `__proto__` property, attackers can overwrite properties of the base object prototype, leading to potential code execution or denial-of-service conditions.

## Attack Chain

1. Attacker crafts a JSON object containing a `__proto__` property with malicious values.
2. The application parses the malicious JSON object, potentially from an untrusted source (e.g., user input or external API).
3. The `objDeepCopy` function in `@nevware21/ts-utils` is called with the malicious object as an argument.
4. The `objDeepCopy` function internally uses the vulnerable `_copyProps` function.
5. The `_copyProps` function iterates over the properties of the malicious object using `for...in`.
6. Due to the absence of `hasOwnProperty` checks, the `__proto__` property is processed.
7. The `__proto__` property's value is used to modify the prototype of the target object.
8. All subsequently created objects in the application inherit the polluted prototype, potentially leading to code execution or denial of service.

## Impact

Successful exploitation of this vulnerability allows an attacker to pollute the prototype of all objects in the application. This can lead to unexpected behavior, code execution, or denial-of-service conditions. The vulnerability affects applications using `@nevware21/ts-utils` versions 0.13.0 and earlier that process untrusted JSON input. This vulnerability has a high severity due to its potential to compromise the integrity and availability of affected applications.

## Recommendation

*   Upgrade to a version of `@nevware21/ts-utils` that includes the fix for CVE-2026-46681.
*   Apply the suggested fix to the vulnerable `_copyProps` function by adding an `objHasOwnProperty` check and filtering `__proto__`, `constructor`, and `prototype` keys.
*   Deploy the Sigma rule "Detect Prototype Pollution via __proto__ Modification" to identify attempts to exploit this vulnerability based on registry modifications that target `__proto__`.
*   Implement input validation to sanitize JSON data before processing it with `objDeepCopy`, filtering out potentially malicious properties like `__proto__`.
*   Audit existing code that uses `@nevware21/ts-utils` to ensure that it does not process untrusted JSON input without proper sanitization.
