---
title: Denial of Service Vulnerability in find-my-way Node.js Router
slug: 2026-07-dos-find-my-way
description: A remotely triggerable Denial of Service (DoS) vulnerability exists in the 'find-my-way' router when used with Node.js HTTP/2 servers. Malicious HTTP/2 method values, such as 'constructor' or '__proto__', can be passed to the 'lookup()' function, which then indexes these values against internal data structures. This leads to a crash when the code attempts to access properties of these unexpected values, such as 'currentNode.prefix.length', causing the server to become unavailable. Users are advised to upgrade to version 9.7.0 or validate HTTP methods before processing.
date: "2026-07-23T19:35:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - nodejs
  - http2
  - vulnerability
products:
  - find-my-way (<= 9.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remotely triggerable Denial of Service (DoS) vulnerability exists in the 'find-my-way' router when used with Node.js HTTP/2 servers. Malicious HTTP/2 method values [...] can be passed to the 'lookup()' function.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This leads to a crash [...] causing the server to become unavailable.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c96f-x56v-gq3h
rules:
  - title: Detects CVE-2026-47219 Exploitation - find-my-way DoS via Malicious HTTP Method
    description: Detects CVE-2026-47219 exploitation - HTTP/2 requests using unusual method names like 'constructor' or '__proto__' to trigger a Denial of Service in the 'find-my-way' Node.js router.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

A high-severity Denial of Service (DoS) vulnerability, identified as CVE-2026-47219, affects the `find-my-way` Node.js router versions up to 9.6.0 when used in conjunction with HTTP/2 servers. This vulnerability allows remote attackers to trigger a server crash by sending HTTP/2 requests with specially crafted method names. The `find-my-way` router, commonly used in Node.js applications, misinterprets certain HTTP method values (e.g., `constructor`, `__proto__`, `toString`) due to a flaw in its `lookup()` and `find()` functions. This leads to an attempt to access properties on unintended JavaScript objects, causing the application to terminate unexpectedly. This vulnerability poses a significant risk to the availability of affected web services, making them susceptible to remote DoS attacks.

## Attack Chain

1. An attacker sends a specially crafted HTTP/2 request to a Node.js server running `find-my-way` versions up to 9.6.0.
2. The request includes a malicious HTTP method name, such as `constructor` or `__proto__`, within the HTTP/2 method field.
3. The `find-my-way` router receives this request and processes the `req.method` value using its internal `lookup()` and `find()` functions.
4. The `find()` function attempts to use the malicious method string (e.g., `constructor`) to index `this.trees[method]`.
5. Due to JavaScript's prototype chain behavior, this lookup resolves to an unexpected inherited object property instead of an intended router node.
6. The router code then attempts to access properties, such as `currentNode.prefix.length`, on this non-router object.
7. This action results in an unhandled exception and crashes the Node.js application, leading to a Denial of Service.

## Impact

Successful exploitation of CVE-2026-47219 leads to a complete Denial of Service for the affected Node.js HTTP/2 server. Each malicious request can cause the application to crash, rendering the service unavailable to legitimate users. There is no information regarding the number of specific victims or sectors targeted, but any organization using `find-my-way` with Node.js HTTP/2 is potentially vulnerable. The primary consequence is the disruption of service, which can lead to reputational damage, financial loss, and interruption of critical operations for businesses reliant on these applications.

## Recommendation

* Upgrade all instances of the `find-my-way` package to version 9.7.0 or higher to mitigate CVE-2026-47219.
* Deploy the Sigma rule included in this brief to your SIEM and monitor web server logs for anomalous HTTP method names to detect attempts at exploiting CVE-2026-47219.
* As a temporary workaround, validate HTTP methods before processing them with `find-my-way` if immediate upgrade to version 9.7.0 is not feasible.
