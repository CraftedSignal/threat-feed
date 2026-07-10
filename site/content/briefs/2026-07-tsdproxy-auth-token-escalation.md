---
title: TSDProxy Internal Authentication Token Vulnerability Leading to Management API Escalation
slug: 2026-07-tsdproxy-auth-token-escalation
description: A critical vulnerability in TSDProxy allows its internal per-process authentication token to be unconditionally forwarded to proxied backend services when `identityHeaders` is enabled, enabling an attacker with code execution on a co-located backend to replay the token to the local TSDProxy management API (port 8080) and bypass authentication, leading to full management API control.
date: "2026-07-10T21:45:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - privilege-escalation
  - authentication-bypass
  - tsdproxy
  - go
vendors:
  - almeidapaulopt
products:
  - tsdproxy < 1.4.4-0.20260603142855-434819b4421e
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The attacker captures the `x-tsdproxy-auth-token` from the HTTP headers received by the backend.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker uses a tool like `curl` to craft an HTTP request from the local host, sending the captured `x-tsdproxy-auth-token` and an arbitrary `x-tsdproxy-id` to the TSDProxy management API at `127.0.0.1:8080`.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: A backend that receives this token can replay it from localhost to the management port with an arbitrary `x-tsdproxy-id` value, bypassing Tailscale authentication entirely.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'An attacker with code execution in any backend proxied by tsdproxy (on the same host) gains full management API control: restart or pause all proxied services (DoS)...'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g936-7jqj-mwv8
iocs:
  - type: url
    value: http://localhost:3000/debug/headers
ioc_counts:
  url: 1
rules:
  - title: Detect TSDProxy Management API Authentication Bypass Attempt
    description: Detects attempts to bypass TSDProxy management API authentication by replaying a stolen internal token from localhost, indicated by specific HTTP headers in process command lines targeting 127.0.0.1:8080.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
      - T1550.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical vulnerability (GHSA-g936-7jqj-mwv8) has been identified in TSDProxy, a Tailscale proxy service. This vulnerability arises because TSDProxy, by default, forwards its internal per-process authentication token (`x-tsdproxy-auth-token`) to all proxied backend services when the `identityHeaders` feature is enabled. This token is crucial for the management HTTP server to trust forwarded Tailscale identity claims. An attacker who has achieved code execution on a backend service co-located on the same host or within the same network namespace as TSDProxy can capture this token. By replaying the stolen token, along with a crafted `x-tsdproxy-id` header, to TSDProxy's local management API (typically on `127.0.0.1:8080`), the attacker can bypass authentication entirely. This grants them full control over the TSDProxy management API, enabling a range of malicious actions, including service disruption and sensitive information exposure. The vulnerability affects `go/github.com/almeidapaulopt/tsdproxy` versions prior to `1.4.4-0.20260603142855-434819b4421e`.

## Attack Chain

1. TSDProxy is deployed with the `identityHeaders` configuration enabled (this is the default setting).
2. A backend service is deployed on the same host as TSDProxy, within a Docker container in host-network-mode, or in a container sharing TSDProxy's network namespace.
3. An attacker successfully gains code execution on the co-located backend service.
4. As TSDProxy forwards requests to the compromised backend, it unconditionally injects its internal `x-tsdproxy-auth-token` into the HTTP request headers.
5. The attacker, having control of the backend, captures the `x-tsdproxy-auth-token` from the incoming HTTP request headers.
6. From the compromised backend, the attacker crafts and executes an HTTP request (e.g., using `curl`) to the TSDProxy management API at `127.0.0.1:8080`. This request includes the stolen `x-tsdproxy-auth-token` and an arbitrary `x-tsdproxy-id` header.
7. TSDProxy's management API, designed to trust requests from localhost with a valid `x-tsdproxy-auth-token`, grants the attacker full administrative control without requiring proper Tailscale authentication.

## Impact

Successful exploitation of this vulnerability leads to full compromise of the TSDProxy management API. An attacker can leverage this access to perform various damaging actions, including restarting or pausing all proxied services, effectively causing a Denial of Service (DoS) condition. They can also enumerate all proxy configurations, exposing sensitive details about the backend network topology and service configurations. Furthermore, the attacker can trigger webhook deliveries configured within TSDProxy, potentially leading to Server-Side Request Forgery (SSRF) if webhook URLs are external or sensitive.

## Recommendation

* Update `go/github.com/almeidapaulopt/tsdproxy` to version `1.4.4-0.20260603142855-434819b4421e` or newer immediately, as outlined in the GitHub Advisory GHSA-g936-7jqj-mwv8.
* Deploy the Sigma rule "Detect TSDProxy Management API Authentication Bypass Attempt" to your SIEM solution to detect suspicious process creations attempting to exploit this vulnerability.
* Implement network monitoring for outbound HTTP connections originating from backend processes and destined for `127.0.0.1:8080`.
* Block connections to `127.0.0.1:8080` from untrusted or non-whitelisted processes if possible, to mitigate unauthorized access to the TSDProxy management API.
