---
title: ApostropheCMS Server-Side Prototype Pollution via apos.util.set
slug: 2026-08-apostrophe-prototype-pollution
description: A server-side prototype pollution vulnerability in ApostropheCMS allows an authenticated editor to bypass authorization for all subsequent API requests by polluting Object.prototype via the $pullAll patch operator.
date: "2026-08-01T01:47:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - ApostropheCMS
products:
  - ApostropheCMS (<= 4.30.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A confirmed gadget in publicApiCheck() causes this to bypass authorization on all piece-type REST API endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-53609
    cvss: 9.1
    epss: 0.00237
references:
  - https://github.com/advisories/GHSA-6h5j-32cf-4253
  - CVE-2026-53609
rules:
  - title: Detect CVE-2026-53609 Exploitation - Prototype Pollution Attempt in PATCH Request
    description: Detects exploitation attempts against ApostropheCMS by identifying prototype manipulation attempts in JSON PATCH bodies.
    platform: sigma
    severity: critical
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

ApostropheCMS versions up to and including 4.30.0 contain a critical server-side prototype pollution vulnerability within the `apos.util.set()` function. The flaw occurs because the function fails to sanitize properties such as `__proto__`, `constructor`, or `prototype` during path traversal. An authenticated user with editor-level privileges can exploit this by sending a crafted PATCH request utilizing the `$pullAll` operator to inject malicious properties into the global `Object.prototype`.

This pollution creates a persistent state within the Node.js process. Specifically, the gadget `publicApiCheck()` fails to correctly enforce authorization once `Object.prototype.publicApiProjection` is set, leading to a process-wide bypass for all REST API piece-type endpoints. This allows unauthenticated users to access sensitive data endpoints that would otherwise be restricted, with the effect persisting until the Node.js process is restarted.

## Attack Chain

1. Attacker obtains valid credentials for an editor-level account on the target ApostropheCMS instance.
2. Attacker authenticates to the application to obtain a valid session token via the login API.
3. Attacker crafts a PATCH request targeting a document, embedding the `$pullAll` operator in the request body.
4. The payload uses dot-notation `__proto__.publicApiProjection` to trigger the unsafe `apos.util.set()` path traversal.
5. The application backend processes the request and mutates the global `Object.prototype`, injecting `publicApiProjection: []`.
6. Future requests from any user, including unauthenticated users, hit the application endpoints.
7. The `publicApiCheck()` logic evaluates the inherited (polluted) `publicApiProjection` property, causing the authorization check to skip.
8. Unauthenticated users retrieve sensitive data from protected REST API endpoints.

## Impact

Successful exploitation results in a complete, persistent authorization bypass for all REST API endpoints across the entire Node.js process. This affects multiple sensitive endpoints, including `@apostrophecms/user` and `@apostrophecms/global`. Because the pollution resides in the global prototype object, it remains effective for the lifetime of the process, impacting every visitor until a server restart occurs. This vulnerability is applicable in any multi-user deployment where editor-level accounts exist.

## Recommendation

1. Upgrade ApostropheCMS immediately to a patched version that implements input validation in `apos.util.set()` and `implementPatchOperators()`.
2. Deploy web server or WAF rules to inspect PATCH requests for `__proto__`, `constructor`, or `prototype` strings within the request body.
3. Restrict access to API endpoints to known safe IP ranges where possible to mitigate the impact of the bypass.
4. Monitor application logs for anomalous PATCH requests containing prototype traversal patterns.
