---
title: Rouille HTTP Request Smuggling Vulnerability (CVE-2026-67182)
slug: 2026-07-rouille-http-smuggling
description: An HTTP request smuggling vulnerability, identified as CVE-2026-67182, in Rouille versions 0.3.3 through 3.6.2 allows remote attackers to bypass access controls by injecting bare line feed characters (0x0A) into client-supplied request header values, causing upstream backends to misinterpret subsequent data as a separate, attacker-controlled HTTP request.
date: "2026-07-28T17:20:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - http-request-smuggling
  - access-control-bypass
  - web-application
  - defense-evasion
products:
  - Rouille 0.3.3
  - Rouille 3.6.2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1592
    technique_name: Network Boundary Bridging
    evidence: Rouille 0.3.3 through 3.6.2 contains an HTTP request smuggling vulnerability that allows remote attackers to bypass access controls by injecting bare line feed characters (0x0A) into client-supplied request header values that are copied verbatim to upstream connections without validation.
    confidence_band: high
cves:
  - id: CVE-2026-67182
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67182
---

Rouille, a Rust web framework, contains a critical HTTP request smuggling vulnerability, tracked as CVE-2026-67182, affecting versions 0.3.3 through 3.6.2. This flaw enables remote attackers to bypass access control mechanisms implemented by the Rouille application. The vulnerability stems from the framework's handling of client-supplied request header values, which are copied verbatim to upstream connections without proper validation. Attackers exploit this by injecting bare line feed characters (0x0A) into these header values, effectively crafting a complete additional HTTP request within the original one. Upstream backends, such as Go net/http and Python http.server, then incorrectly interpret this smuggled request as legitimate, allowing the attacker to execute arbitrary actions with chosen methods, paths, and headers, bypassing the intended security controls. This vulnerability poses a significant risk to the integrity and confidentiality of web applications using affected Rouille versions.

## Attack Chain

1. The attacker crafts an initial HTTP request targeting a Rouille-based web application.
2. Within a client-supplied request header value, the attacker injects a bare line feed character (0x0A), followed by a complete, secondary HTTP request (the "smuggled request").
3. The Rouille application, vulnerable due to improper validation, receives this malformed request.
4. Rouille copies the unvalidated header, including the injected line feed and the smuggled request, verbatim to an upstream backend server (e.g., one running Go net/http or Python http.server).
5. The upstream backend server processes the received data stream.
6. Due to the bare line feed, the backend incorrectly parses the latter portion of the original header as a distinct, attacker-controlled HTTP request.
7. This smuggled request bypasses the access control logic and authorization checks that were intended to be enforced by the Rouille handler.
8. The backend server then executes the smuggled request with attacker-defined method, path, and headers, leading to unauthorized actions or data access.

## Impact

Successful exploitation of CVE-2026-67182 allows remote attackers to completely bypass access controls within affected Rouille applications. This can lead to unauthorized access to sensitive data, execution of privileged functions, or manipulation of application state that would otherwise be restricted. While no specific victim counts or targeted sectors are mentioned, any organization utilizing Rouille versions 0.3.3 through 3.6.2 in internet-facing web applications is at risk. The practical implications include data breaches, defacement, or other forms of system compromise, depending on the capabilities exposed by the bypassed access controls.

## Recommendation

* Patch CVE-2026-67182 on all affected Rouille installations immediately by upgrading to a fixed version beyond 3.6.2.
* Implement a Web Application Firewall (WAF) or reverse proxy configured to normalize HTTP requests and explicitly reject requests containing unencoded line feed characters (0x0A) or other anomalous patterns in header values to mitigate HTTP request smuggling attempts.
