---
title: Axios Prototype Pollution Vulnerability Leads to Request Hijacking and Data Exfiltration
slug: 2024-01-03-axios-prototype-pollution
description: Axios versions 0.19.0 through 1.13.6 are vulnerable to prototype pollution, allowing attackers to intercept and modify JSON responses, hijack HTTP requests, and exfiltrate sensitive data by polluting the Object.prototype with keys like `parseReviver` and `transport`.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prototype-pollution
  - request-hijacking
  - data-exfiltration
  - axios
  - javascript
vendors:
  - lodash
products:
  - axios
  - lodash < 4.17.21
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-pf86-5x62-jrwf
rules:
  - title: Detect Axios HTTP Transport Hijacking
    description: Detects potential HTTP request hijacking attempts by monitoring for modifications to the `transport` property of the `Object.prototype`.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Axios parseReviver Pollution
    description: Detects attempts to pollute the `parseReviver` property of `Object.prototype`, potentially leading to response tampering and data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Axios, a popular HTTP client library, is vulnerable to prototype pollution attacks affecting versions 0.19.0 through 1.13.6. This vulnerability arises from the insecure merging of configuration options within the `mergeConfig` function, which lacks proper checks for own properties. By polluting the `Object.prototype` with malicious keys, such as `parseReviver` and `transport`, attackers can inject code into the request processing flow. This allows for the interception and modification of JSON responses before they reach the application, as well as full hijacking of HTTP requests, exposing sensitive information like credentials, headers, and request bodies. Successful exploitation requires a separate source of prototype pollution within the same process, such as a vulnerable version of lodash ( < 4.17.21).

## Attack Chain

1.  An attacker exploits a separate prototype pollution vulnerability (e.g., in lodash < 4.17.21) to pollute the `Object.prototype` with a malicious `parseReviver` or `transport` property.
2.  The application initiates an HTTP request using Axios.
3.  Axios' `mergeConfig` function merges the default configurations with the request-specific configurations without properly checking for own properties.
4.  Due to the prototype pollution, the malicious `parseReviver` or `transport` property from `Object.prototype` is used in the merged configuration.
5.  If `parseReviver` is polluted, the `JSON.parse` function within Axios uses the malicious reviver function, allowing the attacker to inspect and modify the response body. This could lead to data exfiltration or tampering with application logic.
6.  If `transport` is polluted, Axios uses the attacker-controlled transport object for the HTTP request, granting the attacker full access to request details (URL, headers, credentials).
7.  The attacker logs or forwards the intercepted request data (credentials, headers, body) to an external attacker-controlled server.
8.  The hijacked request proceeds normally, and the application receives the (potentially modified) response.

## Impact

Successful exploitation of this prototype pollution vulnerability can have severe consequences. Attackers can silently modify JSON responses, leading to data corruption or unauthorized privilege escalation within the application. Full HTTP request hijacking enables the exfiltration of sensitive information, including API keys, user credentials, and other confidential data transmitted in headers or the request body. Applications relying on Axios for secure communication are vulnerable, potentially affecting numerous users and services. This vulnerability affects applications using Axios versions 0.19.0 through 1.13.6 and using the Node.js http adapter.

## Recommendation

*   Upgrade to a patched version of Axios that addresses the prototype pollution vulnerability.  However, the advisory states that PR #7369 does not fully resolve the vulnerability and further patches are required.
*   As a temporary mitigation, sanitize or filter user-supplied input to prevent prototype pollution attacks affecting `Object.prototype`, particularly if using libraries like lodash < 4.17.21.
*   Deploy the Sigma rule `Detect Axios HTTP Transport Hijacking` to identify potential attempts to hijack HTTP requests via prototype pollution.
*   Enable detailed logging for HTTP requests and responses to facilitate the detection of unusual data modifications or suspicious network activity.
