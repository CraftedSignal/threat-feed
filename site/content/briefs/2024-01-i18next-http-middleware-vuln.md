---
title: i18next-http-middleware Prototype Pollution and Path Traversal Vulnerability
slug: 2024-01-i18next-http-middleware-vuln
description: Versions of i18next-http-middleware before 3.9.3 are vulnerable to prototype pollution, path traversal, and server-side request forgery (SSRF) due to improper validation of user-controlled language and namespace parameters, potentially leading to denial of service or remote code execution.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - path-traversal
  - ssrf
  - denial-of-service
  - i18next
vendors:
  - npm
products:
  - i18next-http-middleware
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5fgg-jcpf-8jjw
rules:
  - title: Detect Prototype Pollution Attempt via i18next HTTP Middleware
    description: Detects attempts to exploit the prototype pollution vulnerability in i18next-http-middleware by checking for `__proto__`, `constructor`, or `prototype` in the `lng` or `ns` parameters.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal Attempt via i18next HTTP Middleware
    description: Detects attempts to exploit path traversal vulnerability in i18next-http-middleware by checking for directory traversal sequences in the `lng` or `ns` parameters.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

i18next-http-middleware versions prior to 3.9.3 are susceptible to prototype pollution, path traversal, and SSRF attacks. The vulnerability stems from the insufficient validation of the `lng` (language) and `ns` (namespace) parameters passed via HTTP requests to the `getResourcesHandler` and the `missingKeyHandler`. These handlers, intended to serve localization resources, expose attack surface because they process user-controlled input without proper sanitization. This allows attackers to manipulate object properties, access unintended files or internal services, and cause denial-of-service conditions. The vulnerability was discovered via an internal security audit. Defenders should upgrade to version 3.9.3 to remediate the risks.

## Attack Chain

1.  The attacker crafts an HTTP GET request to the `/locales/resources.json` endpoint, targeting the `getResourcesHandler`.
2.  The request includes malicious `lng` and `ns` query parameters, such as `lng=__proto__&ns=isAdmin`, or `ns=../../etc/passwd`.
3.  The `getResourcesHandler` extracts the `lng` and `ns` parameters without sufficient validation.
4.  The `lng` and `ns` values are passed to `utils.setPath(resources, [lng, ns], ...)` which allows writing to the Object prototype if `lng` is `__proto__`.
5.  The `lng` and `ns` values are passed to `i18next.services.backendConnector.load(languages, namespaces, ...)` to load resource bundles. With filesystem or HTTP backends, this can enable path traversal or SSRF if `ns` or `lng` contain malicious path segments.
6.  Alternatively, the attacker sends a POST request with a body containing a malicious `__proto__` key to `missingKeyHandler`, for example `{"__proto__": {"isAdmin": true}}`.
7.  The `missingKeyHandler` iterates over the request body using `for...in`, including inherited prototype properties, and forwards the malicious data into `saveMissing`.
8.  Successful exploitation leads to prototype pollution, arbitrary file access, SSRF, or denial of service.

## Impact

Successful exploitation can have significant consequences. Prototype pollution allows attackers to manipulate object properties globally, leading to broken authorization checks (e.g., bypassing `if (user.isAdmin)`), type confusion errors, or potentially remote code execution. Path traversal enables access to sensitive files on the server, like configuration files or password databases, while SSRF allows attackers to interact with internal services. Finally, the unbounded growth of the `i18next.options.ns` list and repeated backend load calls can lead to denial of service due to memory and CPU exhaustion. This can impact availability of the service and potentially other services on the same host.

## Recommendation

*   Upgrade to `i18next-http-middleware` version 3.9.3 or later to address the vulnerabilities.
*   Deploy the Sigma rules provided below to detect exploitation attempts targeting the `getResourcesHandler` and `missingKeyHandler` endpoints.
*   If upgrading is not immediately feasible, implement a WAF rule as a partial mitigation to block requests containing `__proto__`, `constructor`, `prototype`, `..`, or control characters in `lng`/`ns` query parameters or body keys as suggested in the advisory.
