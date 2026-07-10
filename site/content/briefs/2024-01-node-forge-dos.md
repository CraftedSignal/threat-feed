---
title: Node-Forge Denial of Service via modInverse(0)
slug: 2024-01-node-forge-dos
description: The node-forge library is vulnerable to a denial of service (DoS) due to an infinite loop in the BigInteger.modInverse() function when called with a zero value, leading to application unresponsiveness and high CPU usage.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - node-forge
  - javascript
  - cryptography
vendors:
  - Node-Forge
products:
  - node-forge
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-5m6q-g25r-mvwx
rules:
  - title: Detect Node.js Process High CPU Usage
    description: Detects sustained high CPU usage by Node.js processes, potentially indicating a DoS condition related to node-forge modInverse vulnerability.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect modInverse call with zero value
    description: Detects calls to modInverse with a zero value within a Node.js process, indicating a potential DoS attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Node.js Process with Specific Forge Library Path
    description: Detects Node.js processes running code from the node-forge library, specifically looking at potential calls to the vulnerable jsbn.js file. This is a preventative measure to track usage of the affected library.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

The node-forge library, a widely used cryptographic tool in JavaScript environments, contains a denial-of-service vulnerability in its BigInteger implementation (jsbn.js). Specifically, the `modInverse()` function, which calculates the modular multiplicative inverse, enters an infinite loop when invoked with a zero value. This occurs because the Extended Euclidean Algorithm within `modInverse()` lacks input validation for zero values, leading to an unreachable exit condition. An attacker can exploit this vulnerability by crafting inputs that trigger the `modInverse()` function with a zero value, causing the Node.js process to hang and rendering the application unavailable. This issue affects all versions of node-forge, including the latest (v1.3.1 as of the report), and can impact applications that process untrusted cryptographic parameters. The vulnerability was reported in March 2026.

## Attack Chain

1.  Attacker identifies an application using node-forge and exposing cryptographic operations that involve modular arithmetic.
2.  Attacker crafts a malicious input, specifically designed to result in a zero value being passed to the `modInverse()` function. This could be through DSA/ECDSA signature manipulation or custom RSA/Diffie-Hellman implementations.
3.  The application receives the malicious input via a network request or other external data source.
4.  The application processes the input, leading to a call to `BigInteger.modInverse(m)` in `lib/jsbn.js` with a zero value as the `this` argument.
5.  The `modInverse()` function's Extended Euclidean Algorithm enters an infinite loop due to the missing zero-value check.
6.  The Node.js event loop becomes blocked, preventing the application from processing further requests.
7.  The application becomes unresponsive, resulting in a denial of service.
8.  The server process consumes 100% CPU, exacerbating the DoS impact.

## Impact

A successful attack can cause a complete Denial of Service (DoS). The Node.js process will hang indefinitely, blocking the event loop and rendering the application unresponsive to all subsequent requests. This vulnerability affects any application processing untrusted cryptographic parameters using node-forge. As node-forge has millions of weekly downloads on npm, this poses a significant risk to a large number of applications. The impact is primarily on availability, as the application becomes completely unusable until the process is manually restarted or a fix is deployed.

## Recommendation

*   Upgrade to node-forge version 1.4.0 or later, which includes a fix for this vulnerability (CVE-2026-33891).
*   Implement input validation to prevent zero values from being passed to the `modInverse()` function in `lib/jsbn.js`. Specifically, add a check for `this.signum() == 0` as described in the "Suggested Fix" section of this brief.
*   Monitor CPU usage of Node.js processes for sustained high CPU utilization, which can be an indicator of this DoS attack. Deploy a Sigma rule based on `process_creation` and `cpu_usage` to detect abnormal CPU consumption by node processes.
*   Implement timeouts for cryptographic operations that use `modInverse()` to limit the impact of a potential infinite loop.
