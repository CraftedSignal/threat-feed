---
title: Axios HTTP Adapter Prototype Pollution Vulnerability
slug: 2024-01-axios-prototype-pollution
description: A prototype pollution vulnerability in the Axios HTTP adapter allows an attacker to inject arbitrary HTTP headers into outgoing requests by polluting the Object prototype with specific properties, leading to potential authentication bypass and privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - header-injection
  - axios
  - cve-2026-42035
  - authentication-bypass
  - privilege-escalation
vendors:
  - npm
products:
  - axios (>= 1.0.0, < 1.15.1)
  - axios (<= 0.31.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
cves:
  - id: CVE-2026-42035
    cvss: 7.4
    epss: 0.00083
references:
  - https://github.com/advisories/GHSA-6chq-wfr3-2hj9
rules:
  - title: Detect Prototype Pollution Gadget in Axios HTTP Requests
    description: Detects potential exploitation of the Axios prototype pollution vulnerability by monitoring outgoing HTTP requests for injected headers based on the vulnerable adapter code.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - privilege_escalation
    techniques:
      - T1059.003
    data_sources:
      - network_connection
      - windows
  - title: Detect Potential Prototype Pollution Attempts via getHeaders Modification
    description: Detects modifications to the getHeaders property of the Object prototype, indicative of a potential prototype pollution attempt targeting Axios.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1059.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

A prototype pollution gadget exists within the Axios HTTP adapter (specifically in `lib/adapters/http.js`) that enables attackers to inject arbitrary HTTP headers into outgoing HTTP requests. The vulnerability arises from Axios's reliance on duck-type checking of the data payload. If the `Object.prototype` is polluted with properties like `getHeaders`, `append`, `pipe`, `on`, `once`, and `Symbol.toStringTag`, Axios incorrectly identifies any plain object payload as a `FormData` instance. Consequently, Axios invokes the attacker-controlled `getHeaders()` function, merging the resulting headers into the outgoing request. The vulnerability affects Axios versions greater than or equal to 1.0.0 and less than 1.15.1, as well as versions 0.31.0 and earlier. Exploitation requires a prototype pollution primitive existing somewhere in the application's dependency chain. Successful exploitation can lead to authentication bypass, session fixation, privilege escalation, and IP spoofing.

## Attack Chain

1.  The attacker identifies a prototype pollution vulnerability within a dependency used by the target application (e.g., using `lodash.merge`, `qs`, or `JSON5`).
2.  The attacker injects malicious JavaScript code that pollutes the `Object.prototype` with the following properties and corresponding values: `Symbol.toStringTag` set to `'FormData'`, `append` as an empty function, `getHeaders` as a function returning attacker-controlled headers, `pipe` as a function, and `on` and `once` as functions that return `this`.
3.  The target application uses Axios to make an HTTP request (POST, PUT, or PATCH) with a data payload.
4.  Axios's `lib/adapters/http.js` processes the data payload and performs duck-type checks using `utils.isFormData` and `utils.isFunction(data.getHeaders)`.
5.  Due to the prototype pollution, the `utils.isFormData` function incorrectly identifies the data payload as a FormData instance.
6.  Axios then calls the attacker-controlled `getHeaders()` function.
7.  The attacker's `getHeaders()` function returns a set of malicious HTTP headers.
8.  Axios merges these malicious headers into the outgoing HTTP request, potentially overwriting or adding sensitive headers. The request is sent to the target server.

## Impact

Successful exploitation of this vulnerability can have significant consequences. Attackers can bypass authentication mechanisms by injecting arbitrary `Authorization` headers or escalate privileges by injecting `X-Role` or `X-User-ID` headers. Session fixation is also possible. IP spoofing and WAF bypass can also occur due to header injection. The potential impact could extend beyond a single service if Axios is used for service-to-service communication, where downstream services trust identity headers forwarded from upstream API gateways.

## Recommendation

*   Upgrade Axios to a patched version (>= 1.15.1 or > 0.31.0) to remediate CVE-2026-42035.
*   Apply the provided patch to `lib/adapters/http.js` to include an explicit own-property check on `getHeaders` as a short-term mitigation.
*   Implement input validation and sanitization to prevent prototype pollution vulnerabilities in the application's dependencies, focusing on libraries like `lodash.merge`, `qs`, and `JSON5`.
*   Review and restrict the usage of deep-merge utilities that process attacker-controlled input to minimize the risk of prototype pollution.
*   If Axios is used in service-to-service communication, carefully evaluate the trust boundaries and the potential impact of injected headers on downstream services, considering a Scope Change as outlined in the advisory.
