---
title: js-cookie Prototype Pollution via __proto__ Attribute Injection (CVE-2026-46625)
slug: 2026-05-js-cookie-prototype-pollution
description: The js-cookie library is vulnerable to prototype pollution via the `assign()` function when processing JSON-derived objects, enabling an attacker to inject arbitrary cookie attributes by manipulating the `__proto__` property, as demonstrated by CVE-2026-46625.
date: "2026-05-21T21:21:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - javascript
  - cookie
  - CVE-2026-46625
vendors:
  - npm
products:
  - js-cookie (<= 3.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qjx8-664m-686j
  - CVE-2026-46625
rules:
  - title: Detect Prototype Pollution via JSON __proto__ Attribute in js-cookie
    description: Detects CVE-2026-46625 exploitation — identifies requests where a __proto__ attribute is used to manipulate cookie settings via js-cookie.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect js-cookie Set-Cookie with Suspicious Attributes
    description: Detects potentially malicious Set-Cookie headers where the js-cookie library is used to set suspicious cookie attributes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556.004
    data_sources:
      - webserver
rules_count: 2
---

The `js-cookie` library, versions 3.0.5 and earlier, contains a prototype pollution vulnerability (CVE-2026-46625) within its internal `assign()` function. This function copies properties from source objects to a target object using `for...in` loops and plain assignment. When processing a source object derived from JSON (e.g., via `JSON.parse`), the `__proto__` member becomes an own enumerable property. The `assign` function iterates over this property and inadvertently triggers the `Object.prototype.__proto__` setter. This results in a per-instance prototype pollution where attacker-controlled keys are inherited by the merged `attributes` object, allowing modification of cookie attributes.

## Attack Chain

1. Attacker crafts a JSON payload containing a `__proto__` property with malicious cookie attributes (e.g., domain, secure, samesite, expires, path).
2. The application fetches configuration data from a backend endpoint, parsing the JSON response using `JSON.parse`.
3. The parsed JSON data, containing the attacker's payload, is passed as the `attributes` argument to `Cookies.set()`, `Cookies.remove()`, `Cookies.withAttributes()`, or `Cookies.withConverter()`.
4. The `assign()` function within `js-cookie` iterates over the attacker-controlled `__proto__` property in the source object.
5. The `target[key] = source[key]` assignment triggers the `Object.prototype.__proto__` setter on the target object.
6. The attacker-provided cookie attributes are added to the prototype of the merged attributes object.
7. The `set()` function enumerates the merged object and includes the attacker-injected attributes in the `Set-Cookie` header.
8. The browser receives the `Set-Cookie` header with the attacker-controlled attributes, potentially leading to session hijacking or other security issues.

## Impact

Applications that use `js-cookie` and forward JSON-derived objects as the `attributes` argument to `Cookies.set`, `Cookies.remove`, `Cookies.withAttributes`, or `Cookies.withConverter` are vulnerable. This pattern is common when cookie configurations are loaded from backend APIs. Successful exploitation allows attackers to control cookie attributes like `domain`, `secure`, and `samesite`, potentially leading to cross-site scripting (XSS) or session fixation attacks. A sample payload `{"__proto__":{"domain":"evil.example","secure":"false","samesite":"None"}}` results in cookies being set for the attacker's domain.

## Recommendation

*   Upgrade to a patched version of `js-cookie` that addresses the prototype pollution vulnerability.
*   Apply the patch suggested in the advisory to `src/assign.mjs` to prevent the `__proto__` property from being processed.
*   Implement input validation to sanitize or reject JSON payloads containing the `__proto__` property before they are used as cookie attributes.
*   Deploy the Sigma rule "Detect Prototype Pollution via JSON __proto__ Attribute in js-cookie" to identify exploitation attempts.
*   Review and audit existing code that uses `js-cookie` to ensure that JSON-derived objects are not directly passed as cookie attributes.
