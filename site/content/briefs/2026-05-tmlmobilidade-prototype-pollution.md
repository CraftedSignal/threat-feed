---
title: Prototype Pollution Vulnerability in @tmlmobilidade/utils setValueAtPath Function
slug: 2026-05-tmlmobilidade-prototype-pollution
description: A prototype pollution vulnerability exists in the @tmlmobilidade/utils package before version 20260509.0340.15, specifically affecting the setValueAtPath() function, potentially leading to denial of service or arbitrary code execution.
date: "2026-05-18T17:08:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - javascript
  - npm
  - cve
vendors:
  - GitHub
products:
  - '@tmlmobilidade/utils'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-cmxg-94mg-jq94
  - https://github.com/tmlmobilidade/go/blob/prd/packages/utils/src/generic/value-at-path.ts
rules:
  - title: Detect Prototype Pollution via setValueAtPath
    description: Detects attempts to exploit prototype pollution vulnerabilities via the setValueAtPath function in web applications.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Prototype Pollution in HTTP Requests
    description: Detects HTTP requests attempting to modify the prototype chain using common keywords.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A prototype pollution vulnerability has been identified in the `@tmlmobilidade/utils` npm package, specifically within the `setValueAtPath()` function. This vulnerability affects versions prior to `20260509.0340.15`. Prototype pollution occurs when an attacker can manipulate the properties of JavaScript object prototypes. This can lead to various security issues, including denial of service, arbitrary code execution (in certain environments), or information disclosure. The vulnerability was reported on May 13, 2026, and a patched version was released on May 18, 2026. This vulnerability is tracked as CVE-2026-45325. Defenders should ensure they are running the patched version to prevent potential exploitation.

## Attack Chain

1. An attacker identifies a vulnerable endpoint or function within an application that utilizes the `@tmlmobilidade/utils` package and its `setValueAtPath()` function.
2. The attacker crafts a malicious input designed to manipulate the JavaScript object prototype.
3. The malicious input is sent to the vulnerable application endpoint. This input exploits the `setValueAtPath` function by injecting properties into the prototype.
4. The `setValueAtPath()` function processes the attacker-controlled input without proper sanitization, allowing modification of the object prototype.
5. The attacker injects properties like `__proto__.polluted` or `constructor.prototype.polluted`, which affects all subsequently created objects inheriting from that prototype.
6. The application's logic uses these polluted objects, leading to unexpected behavior or control flow changes.
7. Depending on the application's design, the prototype pollution can lead to denial of service by crashing the application, or potentially remote code execution.
8. If successful, the attacker could gain control over the application's behavior, potentially leading to data theft or further compromise of the system.

## Impact

Successful exploitation of this prototype pollution vulnerability can lead to various adverse effects. An attacker can modify object properties leading to denial of service. Remote code execution might be possible depending on the application's configuration and usage of the polluted objects. The number of affected applications depends on the adoption of the `@tmlmobilidade/utils` package. This type of vulnerability can be particularly damaging as it can affect multiple parts of an application due to the nature of prototype inheritance in JavaScript.

## Recommendation

- Upgrade the `@tmlmobilidade/utils` package to version `20260509.0340.15` or later to remediate the vulnerability (references: GHSA-cmxg-94mg-jq94).
- Implement input validation and sanitization to prevent malicious input from reaching the `setValueAtPath()` function.
- Deploy the Sigma rule to detect potential prototype pollution attempts targeting the vulnerable function (rule: "Detect Prototype Pollution via setValueAtPath").
- Regularly audit and update dependencies to minimize the risk of known vulnerabilities affecting your applications.
- Monitor web server logs for suspicious requests containing prototype pollution payloads (e.g., `__proto__`, `constructor.prototype`) using the log source `webserver`.
