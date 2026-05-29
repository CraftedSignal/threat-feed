---
title: Axios Prototype Pollution Leads to Man-in-the-Middle Vulnerability
slug: 2026-05-axios-prototype-pollution-mitm
description: Axios is vulnerable to a Prototype Pollution attack that can be escalated into a full Man-in-the-Middle (MITM) attack by injecting a malicious proxy configuration via `Object.prototype.proxy`, allowing attackers to intercept, read, and modify all HTTP traffic, including authentication credentials.
date: "2026-05-29T16:05:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prototype-pollution
  - mitm
  - axios
  - javascript
vendors:
  - axios
products:
  - axios
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://github.com/advisories/GHSA-35jp-ww65-95wh
  - https://cwe.mitre.org/data/definitions/1321.html
  - https://cwe.mitre.org/data/definitions/441.html
  - https://github.com/advisories/GHSA-fvcv-3m26-pcqx
  - https://github.com/axios/axios
rules:
  - title: Detect Prototype Pollution via Object.prototype Modification
    description: Detects attempts to modify the Object.prototype, which can be indicative of prototype pollution attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect Inbound Network Connection to Unusual High Port
    description: Detects inbound network connections to a high port (over 1024) on a host, potentially indicating an attacker-controlled proxy listening for intercepted traffic.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Proxy Setting Modification via process
    description: Detects attempts to set a proxy configuration by modifying the Object prototype, which may be indicative of prototype pollution attacks abusing proxy configuration
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The Axios library is vulnerable to a critical Prototype Pollution attack that allows an attacker to achieve a full Man-in-the-Middle (MITM) position. By polluting the `Object.prototype.proxy` property, an attacker can force Axios to route all HTTP requests through an attacker-controlled proxy server, enabling the interception, reading, and modification of all HTTP traffic, including sensitive information like authentication credentials. This vulnerability exists because the `proxy` property is not defined in Axios' default configuration, causing the library to traverse the prototype chain when resolving the `config.proxy` value. This allows an attacker to inject a malicious proxy configuration, leading to the MITM attack. All versions of Axios are affected.

## Attack Chain

1. An attacker identifies a prototype pollution vulnerability in a separate library (e.g., `qs`, `minimist`, `lodash`, `body-parser`) used by the application.
2. The attacker exploits this vulnerability to inject a malicious proxy configuration into `Object.prototype.proxy`, specifying the attacker's proxy server address and port.
3. The application makes an HTTP request using Axios, without explicitly configuring a proxy.
4. Axios' HTTP adapter at `lib/adapters/http.js` attempts to resolve the `config.proxy` value.
5. Due to the absence of a `proxy` property in Axios' default configuration, JavaScript traverses the prototype chain and finds the polluted `Object.prototype.proxy` value.
6. The `setProxy()` function uses the malicious proxy configuration to route the HTTP request through the attacker's proxy server.
7. The attacker intercepts the request, gaining access to all request headers, including sensitive information like `Authorization` tokens.
8. The attacker can modify the request or response before forwarding it to the intended destination, completing the MITM attack.

## Impact

Successful exploitation of this vulnerability allows an attacker to intercept all HTTP traffic generated by the Axios library within an application. This includes sensitive information such as `Authorization` headers containing credentials, cookies, API keys, and request bodies. The attacker can also modify responses, inject malicious data, and redirect authentication flows. The attack is invisible to the developer, as requests appear to complete normally with attacker-controlled responses. This could lead to complete compromise of application data, including internal API keys, session tokens, and user passwords.

## Recommendation

- Apply mitigations to prevent prototype pollution in your application's dependencies to prevent this issue from being exploitable (CWE-1321).
- Deploy the Sigma rule to detect prototype pollution attempts by monitoring `Object.prototype` property modifications (see below).
- Update to a patched version of Axios when one becomes available with a fix addressing `hasOwnProperty` checks or null-prototype object usage for merged configurations.
- As a temporary measure, if possible, ensure the `proxy` configuration is explicitly set in Axios configurations to prevent prototype traversal.
