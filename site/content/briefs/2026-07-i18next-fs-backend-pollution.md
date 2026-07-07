---
title: i18next-fs-backend Prototype Pollution via Crafted Missing-Key String (CVE-2026-48713)
slug: 2026-07-i18next-fs-backend-pollution
description: Untrusted input can exploit a prototype pollution vulnerability (CVE-2026-48713) in `i18next-fs-backend` versions prior to 2.6.6, particularly via `i18next-http-middleware`'s `missingKeyHandler`, by submitting crafted missing-key strings that leverage the `keySeparator` to write arbitrary properties onto `Object.prototype`, leading to crashes, configuration poisoning, or security bypasses.
date: "2026-07-03T10:45:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:i18next:i18next-fs-backend:*:*:*:*:*:node.js:*:*
tags:
  - prototype-pollution
  - node.js
  - web-application
  - vulnerability
products:
  - i18next-fs-backend < 2.6.6
  - i18next-http-middleware < 3.9.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: '`i18next-fs-backend` ... when used ... via `i18next-http-middleware`''s `missingKeyHandler` exposed to untrusted input, is vulnerable to prototype pollution via crafted missing-key strings.'
    confidence_band: high
cves:
  - id: CVE-2026-48713
    cvss: 9.1
    epss: 0.00419
references:
  - https://github.com/advisories/GHSA-2933-q333-qg83
  - https://github.com/i18next/i18next-http-middleware/security/advisories/GHSA-f49m-vf83-692w
rules:
  - title: Detect CVE-2026-48713 Exploitation — i18next-fs-backend Prototype Pollution Attempt
    description: Detects exploitation attempts for CVE-2026-48713, where an attacker attempts prototype pollution via a crafted missing-key string containing '__proto__', 'constructor', or 'prototype' in web requests targeting i18next endpoints.
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

Versions of the `i18next-fs-backend` Node.js package prior to 2.6.6 are susceptible to a critical prototype pollution vulnerability, identified as CVE-2026-48713. This flaw arises when the backend is configured to persist missing translation keys, especially when exposed to untrusted user input via components like `i18next-http-middleware`'s `missingKeyHandler`. An attacker can craft a missing-key string, such as `"__proto__.polluted"`, which exploits the package's `keySeparator` splitting logic. This allows the internal `setPath()` function to write arbitrary properties directly onto the global `Object.prototype`, effectively polluting the object. This server-side vulnerability can lead to severe consequences, including application crashes, corrupted translation behavior, configuration poisoning, and potential bypasses of property-based security checks. The vulnerability impacts any Node.js application utilizing the affected versions under the specified configuration.

## Attack Chain

1.  An attacker sends a malicious HTTP request to a web application endpoint that exposes `i18next-http-middleware`'s `missingKeyHandler` to untrusted users.
2.  The request body or query parameter contains a specially crafted missing-key string, such as `__proto__.polluted=value` or `constructor.polluted=value`.
3.  The `i18next-fs-backend` (version ≤ 2.6.5) receives this malicious key string for processing and persistence.
4.  The `Backend.writeFile()` function attempts to process the key and splits it using the configured `keySeparator` (defaulting to `.`), generating an array of segments like `["__proto__", "polluted"]`.
5.  An internal path traversal helper, `getLastOfPath()` in `lib/utils.js`, is called to walk these segments.
6.  Due to the lack of proper validation or guarding against unsafe segments, this walker successfully traverses into `Object.prototype`.
7.  The `polluted` property (or similar) is then created or overwritten on the global `Object.prototype` with the attacker-controlled `value`, achieving prototype pollution.
8.  Subsequent application code that accesses properties on objects without specific checks can be affected by the polluted prototype, leading to application crashes, configuration manipulation, or security bypasses.

## Impact

The successful exploitation of CVE-2026-48713 can have critical consequences for affected Node.js applications. By injecting arbitrary properties into `Object.prototype`, attackers can cause application crashes by corrupting expected object structures, manipulate application configuration settings to alter behavior or gain control, or bypass security checks that rely on specific property values. While no specific victim counts are provided, any Node.js application using `i18next-fs-backend` <= 2.6.5 in combination with an exposed `missingKeyHandler` or similar untrusted input path is at risk. The impact extends across various sectors, particularly those using Node.js for web development and internationalization.

## Recommendation

*   Immediately upgrade `i18next-fs-backend` to version 2.6.6 or higher to patch CVE-2026-48713.
*   Upgrade `i18next-http-middleware` to version 3.9.7 or higher, as it contains a companion defense-in-depth fix.
*   If immediate upgrades are not feasible, ensure the `missingKeyHandler` endpoint of `i18next-http-middleware` is not exposed to untrusted users (e.g., place it behind authentication or remove the route).
*   Disable missing-key persistence (`saveMissing: false`) if accepting writes from untrusted input in your `i18next` configuration.
*   As a workaround, set `keySeparator: false` in your `i18next` options to prevent backend key splitting, noting this will also disable legitimate nested translation keys.
*   Deploy the Sigma rule provided in this brief to your SIEM for detection of exploitation attempts via web server logs.
