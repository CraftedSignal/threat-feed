---
title: parse-nested-form-data Prototype Pollution Vulnerability (CVE-2026-45302)
slug: 2026-05-parse-nested-form-data-prototype-pollution
description: parse-nested-form-data versions 1.0.0 and earlier are vulnerable to prototype pollution via crafted FormData field names, allowing an unauthenticated remote client to mutate `Object.prototype` and potentially corrupt application state, alter control flow, or cause denial of service.
date: "2026-05-18T16:44:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - prototype-pollution
  - javascript
  - web-application
products:
  - parse-nested-form-data (<= 1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xp7r-j8r6-j9h3
  - https://cwe.mitre.org/data/definitions/1321.html
  - https://github.com/dwyl/parse-nested-form-data/commit/527ad58eb486e32438f7198fb88315c20449d792
rules:
  - title: Detect Prototype Pollution Attempt in parse-nested-form-data via FormData
    description: Detects attempts to exploit the prototype pollution vulnerability in parse-nested-form-data by searching for `__proto__`, `constructor`, or `prototype` in FormData field names within HTTP POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The `parse-nested-form-data` library, versions 1.0.0 and earlier, contains a prototype pollution vulnerability. The vulnerability lies in how the `parseFormData()` function handles bracket and dot-notation within FormData field names. By crafting a FormData field name containing `__proto__`, an attacker can manipulate the prototype chain of JavaScript objects. This occurs because the parsing logic doesn't properly filter reserved property keys during the creation of nested objects from the FormData fields. This issue was patched in version 1.0.1.

## Attack Chain

1. An attacker crafts a malicious HTTP request containing a FormData object.
2. The FormData object includes a field with a name containing `__proto__`, such as `__proto__.polluted=yes`.
3. The server-side application receives the HTTP request and extracts the FormData object.
4. The application calls `parseFormData()` to parse the FormData into a nested JavaScript object.
5. The `parseFormData()` function processes the malicious field name without proper sanitization.
6. The `handlePathPart` function within `parseFormData()` uses the `__proto__` segment to traverse onto `Object.prototype`.
7. A property is assigned to `Object.prototype`, polluting the prototype chain for all plain JavaScript objects.
8. Subsequent operations on JavaScript objects may exhibit unexpected behavior due to the prototype pollution, leading to application compromise.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to pollute the prototype chain of JavaScript objects in the affected application. This can lead to various impacts, including: corrupted application state, altered control flow in code that reads properties off objects, and denial of service. The severity of the impact depends on how the application utilizes JavaScript objects and their properties. Multiple applications are vulnerable by using the affected package.

## Recommendation

*   Upgrade to `parse-nested-form-data` version 1.0.1 or later to remediate the vulnerability.
*   If upgrading is not immediately possible, implement the workaround provided in the advisory to validate field names before calling `parseFormData()` to prevent exploitation.
*   Deploy the Sigma rule `Detect Prototype Pollution Attempt in parse-nested-form-data via FormData` to detect exploitation attempts based on HTTP request patterns.
*   Monitor web server logs for POST requests with form data containing `__proto__`, `constructor`, or `prototype` in the field names as described in the vulnerability details.
