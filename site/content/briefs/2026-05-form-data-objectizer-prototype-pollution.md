---
title: form-data-objectizer Prototype Pollution Vulnerability (CVE-2026-46510)
slug: 2026-05-form-data-objectizer-prototype-pollution
description: The form-data-objectizer npm package version 1.0.0 is vulnerable to prototype pollution (CVE-2026-46510) via crafted form keys, allowing an attacker to modify Object.prototype and potentially cause denial-of-service, bypass security checks, or inject unintended values.
date: "2026-05-18T13:28:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - prototype-pollution
  - javascript
  - node.js
products:
  - form-data-objectizer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-m2hg-wjq3-28wq
rules:
  - title: Detect Prototype Pollution via form-data-objectizer
    description: Detects CVE-2026-46510 exploitation — Prototype pollution attempt via form-data-objectizer by detecting '__proto__' in cs-uri-query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Prototype Pollution via constructor.prototype
    description: Detects CVE-2026-46510 exploitation — Prototype pollution attempt via form-data-objectizer by detecting 'constructor[prototype]' in cs-uri-query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The `form-data-objectizer` npm package, version 1.0.0, is susceptible to prototype pollution. This vulnerability arises because the library processes bracket-notation form keys (e.g., `name[sub]`) without properly sanitizing special property names like `__proto__`, `constructor`, or `prototype`. By crafting a specific HTTP form field with a name starting with `__proto__[...]`, an attacker can modify the `Object.prototype`.  This can lead to a range of security issues. This vulnerability was reported on May 18, 2026, and affects Node.js applications using the `form-data-objectizer.toObject()` function to parse incoming form data. The injected properties persist across requests handled by the same process, magnifying the impact.

## Attack Chain

1. An attacker crafts a malicious HTTP form request containing a field with a key starting with `__proto__`, for example, `__proto__[polluted]=yes`.
2. The Node.js application receives the HTTP request and uses the `form-data-objectizer` library to parse the form data.
3. The `toObject()` function in `form-data-objectizer` calls the `treatInitial` function to process the form data.
4. The `treatInitial` function identifies the `__proto__` property and retrieves the corresponding value, which is `Object.prototype`.
5. The `treatSecond` function is then called recursively with the remaining part of the key, such as `polluted`.
6. The `treatSecond` function directly assigns the attacker-controlled value to `Object.prototype[polluted]`, polluting the prototype.
7. All subsequently created objects in the Node.js process inherit the polluted property.
8. The attacker achieves their objective by modifying application behavior or causing a denial-of-service by exploiting the polluted prototype.

## Impact

Successful exploitation of this vulnerability allows an attacker to pollute the prototype of all objects in the Node.js process. This can lead to various consequences, including bypassing `if (obj.isAdmin)` style checks, injecting unintended config values into objects merged with user input, breaking template rendering, and crashing the worker process due to modifications of properties used by other libraries. The vulnerability affects any application using `form-data-objectizer` to parse form data, potentially impacting a wide range of Node.js applications. An unauthenticated attacker can trigger this with a single HTTP request.

## Recommendation

*   Apply the suggested patch provided in the advisory to reject any form key segment equal to `__proto__`, `constructor`, or `prototype` in `form-data-objectizer` to mitigate CVE-2026-46510.
*   Deploy the Sigma rule "Detect Prototype Pollution via form-data-objectizer" to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests containing form fields with names starting with `__proto__`, `constructor`, or `prototype`.
*   Consider using `Object.create(null)` for the result object as a preventative measure, but ensure to also guard against direct writes to `__proto__` as described in the advisory.
