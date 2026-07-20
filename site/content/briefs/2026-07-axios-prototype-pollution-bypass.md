---
title: Axios Node.js HTTP Adapter Vulnerable to Proxy Redirection via Prototype Pollution Bypass
slug: 2026-07-axios-prototype-pollution-bypass
description: A vulnerability in Axios's Node.js HTTP adapter, affecting versions 1.15.2 and 1.16.0, allows an attacker to bypass prototype pollution hardening, enabling redirection of HTTP requests through an attacker-controlled proxy to achieve sensitive information disclosure.
date: "2026-07-20T22:41:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prototype-pollution
  - information-disclosure
  - axios
  - nodejs
vendors:
  - Axios
products:
  - axios (< 1.16.1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Axios’ threat model explicitly treats polluted Object.prototype config reads as high-impact read-side gadgets and states that axios defends reachable config-read gadgets through own-property checks and null-prototype structures. The existing regression tests also assert that a polluted Object.prototype.proxy must not route requests through an attacker proxy. This behavior is therefore a bypass of axios’ existing prototype-pollution hardening
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1040
    technique_name: Network Sniffing
    evidence: 'In a Node.js deployment using the HTTP adapter, an attacker who can trigger prototype pollution elsewhere in the process can cause affected axios requests to be sent through an attacker-controlled proxy... Disclosure of explicit Authorization headers. Disclosure of axios-generated Basic auth headers from config.auth. Disclosure of request metadata: method, absolute URL, Host header. Disclosure of POST body content.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-gcfj-64vw-6mp9
---

A critical vulnerability (GHSA-gcfj-64vw-6mp9) has been identified in the Axios Node.js HTTP adapter, affecting versions `1.15.2` and `1.16.0`. This flaw allows an attacker to bypass Axios's built-in prototype pollution hardening mechanisms, leading to sensitive information disclosure. The vulnerability occurs when a Node.js application uses Axios with a request interceptor that, through common immutable cloning patterns like `{...config}` or `Object.assign({}, config)`, re-materializes the request configuration from a null-prototype object back into a regular object. This re-materialized object then inherits from a polluted `Object.prototype.proxy`, effectively routing all subsequent HTTP requests through an attacker-controlled proxy. The attack requires a separate, initial prototype pollution vulnerability within the Node.js process. This enables the attacker to intercept and exfiltrate credentials such as `Authorization` headers, `Basic auth` details, request metadata, and full request body content, posing a significant risk of data exfiltration and authentication bypass in affected server-side applications.

## Attack Chain

1. Attacker exploits a separate vulnerability (e.g., deserialization, input validation bypass) to achieve arbitrary prototype pollution within a Node.js process.
2. The attacker specifically pollutes `Object.prototype.proxy` with details of an attacker-controlled proxy server (e.g., `{ protocol: 'http', host: 'attacker_ip', port: attacker_port }`).
3. A Node.js application makes an HTTP request using Axios (versions `1.15.2` or `1.16.0`), and a request interceptor clones the configuration using a plain object copy (e.g., `{...config}`).
4. Axios's `mergeConfig` initially creates a null-prototype configuration object to prevent prototype pollution from `Object.prototype`.
5. The request interceptor's cloning action (e.g., `{...config}`) converts this null-prototype object back into a regular object, causing it to inherit from `Object.prototype`.
6. Axios dispatches this re-materialized configuration to the Node.js HTTP adapter without re-hardening or re-normalizing it.
7. The Node.js HTTP adapter attempts to read `config.proxy`, which now resolves to the attacker-controlled proxy server's details from the polluted `Object.prototype.proxy`.
8. Outgoing HTTP requests, including sensitive data such as `Authorization` headers, `Host`, and request body content, are routed through the attacker's proxy, enabling information disclosure.

## Impact

Successful exploitation allows an attacker to intercept and exfiltrate sensitive data from affected Node.js HTTP requests. This includes explicit `Authorization` headers, axios-generated `Basic auth` credentials, full absolute URLs, `Host` headers, and request body content. The attacker's proxy can also return its own response to the Axios client, potentially leading to further compromise or manipulation of application logic. The impact is limited to Node.js deployments using the HTTP adapter and does not affect browser environments or guarantee HTTPS header/body disclosure under normal TLS validation. This can lead to unauthorized access, data breaches, and service disruption.

## Recommendation

* Update Axios to version `1.16.1` or later immediately to apply the patch addressing GHSA-gcfj-64vw-6mp9.
* Review all Axios request interceptors to ensure they do not return regular object clones of the configuration; instead, return the original null-prototype config or clone into a null-prototype object to prevent the bypass.
* If proxy support is not required for specific requests or Axios instances, explicitly set `proxy: false` in the configuration to prevent unintended proxy usage.
* Consider using the Node fetch adapter for affected requests if compatible with your application's requirements.
* Implement robust input validation and sanitization across your application to prevent the initial prototype pollution vulnerability that is a prerequisite for this attack.
