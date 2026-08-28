---
title: Unauthenticated Remote Denial of Service in alos-http
slug: 2026-08-alos-http-dos
description: An unauthenticated remote denial-of-service vulnerability in alos-http allows attackers to crash the server process by sending a single malformed HTTP request starting with a '?' character.
date: "2026-08-28T21:14:12Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:guno1928:alos_http:*:*:*:*:*:*:*:*
tags:
  - dos
  - vulnerability
  - webserver
vendors:
  - guno1928
products:
  - alos-http (< 0.0.0-20260617230736-314b6783e196)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single unauthenticated HTTP request to a path starting with ? triggers out-of-bounds panic in sanitizeRequestPath, crashing entire server.
    confidence_band: high
cves:
  - id: CVE-2026-55484
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-hr6j-w4mw-g9mj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55484
rules:
  - title: Detect CVE-2026-55484 Exploitation - Malformed HTTP Request
    description: Detects HTTP requests containing a path that begins with a '?' character, which triggers an out-of-bounds panic in vulnerable alos-http servers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade alos-http to version 0.0.0-20260617230736-314b6783e196 or later
      owner: IT Operations
      due: 24h
      evidence: Source states versions prior to this are vulnerable
  hunt_leads:
    - lead: 'Search for service restarts associated with ''panic: runtime error: index out of range'' in application logs'
      technique_id: T1499
      data_needed:
        - Application log files
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'The crash log includes ''panic: runtime error: index out of range'''
  mitigation_plan:
    - priority: immediate
      action: Block or inspect requests starting with '?' at the WAF level
      owner: Security Operations
      addresses: CVE-2026-55484
      evidence: The vulnerability is triggered by a malformed request line
---

The alos-http web framework is susceptible to a remote denial-of-service vulnerability (CVE-2026-55484) due to improper input validation in the 'sanitizeRequestPath' function. When the framework receives an HTTP request with a path starting with the '?' character (e.g., 'GET ? HTTP/1.1'), the internal request parser passes the path to 'sanitizeRequestPath'. This function attempts to index the first byte of the path after query string stripping without verifying that the resulting string is non-empty. This results in an out-of-bounds panic. Because this parsing occurs in the connection-worker goroutine before any user-defined middleware or recovery handlers are executed, the panic is unrecoverable, leading to an immediate process crash. This affects HTTP/1.1, HTTP/2, and HTTP/3 protocols, potentially rendering services unavailable until restarted.

## Attack Chain

1. Attacker crafts a malicious HTTP request with a malformed path starting with a '?' character.
2. Attacker transmits the request via TCP (HTTP/1.1 or HTTP/2) or UDP (HTTP/3) to the target alos-http server.
3. The server's connection-worker goroutine receives the request head.
4. The request parser invokes 'sanitizeRequestPath' with the malicious path.
5. The 'sanitizeRequestPath' function strips the query string, resulting in an empty string.
6. The function attempts to access the first index of the empty string.
7. A runtime panic triggers due to an out-of-bounds index access.
8. The entire server process crashes, resulting in total service denial.

## Impact

Successful exploitation results in an immediate and total denial of service for the target application. Because the crash occurs during the request parsing phase before any request logging or middleware execution, the impact is consistent across all deployments using the vulnerable framework versions. The vulnerability has been confirmed in alos-http versions prior to 0.0.0-20260617230736-314b6783e196.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

* Upgrade the alos-http framework to version 0.0.0-20260617230736-314b6783e196 or later immediately to patch CVE-2026-55484.
* Deploy the provided Sigma rule to web application firewalls or reverse proxies to block requests where the URI path begins with a '?' character.
* Monitor webserver access logs for anomalous 400-series status codes or service-level process restarts that lack associated handler logs, which may indicate crash attempts.
