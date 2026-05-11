---
title: '@rvf/set-get Prototype Pollution via Form Data Processing (CVE-2026-44483)'
slug: 2026-05-rvf-prototype-pollution
description: The `@rvf/set-get` library, used by `@rvf/core`, is vulnerable to prototype pollution via form data processing; the `setPath` function does not block the keys `__proto__`, `constructor`, or `prototype` when walking a path, allowing attackers to set arbitrary properties on `Object.prototype` of the running server process via HTTP form submissions (CVE-2026-44483).
date: "2026-05-11T16:11:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - web-application
  - javascript
vendors:
  - rvf
products:
  - '@rvf/set-get'
  - '@rvf/core'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-c567-44rc-m5hq
  - CVE-2026-44483
rules:
  - title: Detect CVE-2026-44483 Exploitation Attempt — Prototype Pollution via __proto__ in Form Data
    description: Detects CVE-2026-44483 exploitation attempt — HTTP POST requests with form data containing `__proto__` in the field name, indicative of prototype pollution attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-44483 Exploitation Attempt — Prototype Pollution via __proto__ in cs-uri-stem
    description: Detects CVE-2026-44483 exploitation attempt — HTTP POST requests with `__proto__` in the URI path, indicative of prototype pollution attempts.
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

The `@rvf/set-get` library, a dependency of `@rvf/core`, is vulnerable to a prototype pollution attack. This vulnerability arises due to the `setPath` function failing to sanitize or block the `__proto__`, `constructor`, and `prototype` keys during path traversal. This flaw allows an attacker to manipulate the `Object.prototype` of the server process by submitting malicious form data to an application using `@rvf/core` for form processing. The vulnerability is present in `@rvf/set-get` versions prior to `7.0.2` (7.x line) and `6.0.4` (6.x line), and is reachable through `@rvf/core` versions that depend on a vulnerable `@rvf/set-get`, like the current `8.1.0` which resolves to `7.0.1` by default. This issue allows attackers to inject arbitrary properties, potentially leading to privilege escalation, denial-of-service, or configuration manipulation.

## Attack Chain

1. An attacker crafts an HTTP POST request containing form data.
2. The form data includes a field name designed for prototype pollution, such as `__proto__[polluted]=yes`.
3. The request is sent to a Remix or React Router application that uses `@rvf/core` to handle form data.
4. The `parseFormData` function within `@rvf/core` processes the incoming form data.
5. `parseFormData` calls `preprocessFormData` which uses the vulnerable `setPath` function from `@rvf/set-get` to flatten the form data into a nested object.
6. `setPath` fails to block the `__proto__` key, allowing the attacker-controlled value to be written to `Object.prototype`.
7. Every plain object created in the server process subsequently inherits the polluted property.
8. This pollution can be exploited to bypass security checks, modify application behavior, or cause a denial of service.

## Impact

Successful exploitation of this vulnerability allows an attacker to set arbitrary properties on the `Object.prototype` of the server process via a single, unauthenticated HTTP request. This pollution persists for the life of the worker process, affecting every subsequent request handled by the same process. The direct consequences depend on the host application and its dependencies. However, typical risks include bypassing authentication checks (`if (obj.isAdmin)`), injecting unintended configuration values, breaking template rendering, and crashing the worker process. The vulnerability leaves no obvious trace in request logs, as the malicious key is not present in the visible output of `preprocessFormData`.

## Recommendation

- Upgrade to `@rvf/set-get` version `7.0.2` or `6.0.4` to patch CVE-2026-44483.
- If a direct upgrade of `@rvf/core` is not feasible, use `npm` or `pnpm` overrides to force the resolution of `@rvf/set-get` to a patched version.
- Deploy the Sigma rules in this brief to detect potential exploitation attempts by looking for requests with malicious field names in HTTP request logs.
