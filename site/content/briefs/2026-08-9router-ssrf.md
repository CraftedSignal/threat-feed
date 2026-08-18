---
title: Unauthenticated SSRF in 9Router OIDC Test Endpoint
slug: 2026-08-9router-ssrf
description: An unauthenticated SSRF vulnerability in the 9Router /api/auth/oidc/test endpoint allows remote attackers to perform internal network scanning and data exfiltration via the issuerUrl parameter.
date: "2026-08-18T00:46:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-56677
  - 9router
vendors:
  - 9Router
products:
  - 9router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The endpoint can be accessed without active session authentication (Unauthenticated), allowing any remote actor with network visibility to the dashboard API endpoints to trigger outbound infrastructure connections.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: An unauthenticated attacker can abuse this behavior to use the 9Router instance as a proxy to conduct internal network topology discovery and port scanning against the hosting infrastructure.
    confidence_band: high
cves:
  - id: CVE-2026-56677
    cvss: 8.6
references:
  - https://github.com/advisories/GHSA-8g4w-4ffg-8vgx
rules:
  - title: Detect CVE-2026-56677 Exploitation - POST to OIDC Test Endpoint
    description: Detects unauthenticated POST requests to the 9Router OIDC test endpoint which is the vector for CVE-2026-56677 SSRF exploitation
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy detection rule for POST /api/auth/oidc/test to identify exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Endpoint documentation in GHSA advisory.
  mitigation_plan:
    - priority: immediate
      action: Patch 9Router to a version greater than 0.5.4.
      owner: IT Operations
      addresses: CVE-2026-56677
      evidence: GHSA advisory recommendations.
---

9Router versions 0.5.4 and earlier are vulnerable to a Server-Side Request Forgery (SSRF) flaw in the /api/auth/oidc/test endpoint. The vulnerability exists because the application accepts a user-controlled 'issuerUrl' parameter and performs an unauthenticated outbound HTTP request to the provided URL without validating the destination. An attacker can force the application to probe internal network infrastructure, including loopback addresses and private IP subnets. 

The impact varies based on the target internal service: if the target is a non-HTTP service, the application leaks error details that confirm internal port accessibility. If the target responds with a JSON structure matching the OIDC configuration schema, the application parses the response and reflects its contents to the requester. This vulnerability, tracked as CVE-2026-56677, requires no authentication, making it a highly accessible vector for internal reconnaissance and potential configuration manipulation within the hosting environment.

## Attack Chain

1. Attacker identifies a 9Router instance reachable via the network.
2. Attacker crafts an HTTP POST request targeting the /api/auth/oidc/test endpoint.
3. Attacker populates the 'issuerUrl' JSON field with a target internal IP address or hostname (e.g., http://127.0.0.1:80).
4. 9Router backend receives the request and, lacking authentication middleware, initiates an outbound 'fetch' request to the specified 'issuerUrl'.
5. The target internal resource receives the request and returns a response (either an error, a raw string, or a valid OIDC JSON configuration).
6. 9Router parses the response; if it matches an OIDC schema, internal metadata is processed and stored by the backend.
7. 9Router reflects the parsed data or error message back to the attacker in the HTTP response body.
8. Attacker uses this feedback loop to map internal network topology or exfiltrate internal configuration data.

## Impact

The vulnerability allows unauthenticated attackers to conduct internal network reconnaissance and perform blind or reflected SSRF attacks. Successful exploitation enables an attacker to map internal services and potentially manipulate the internal application state by feeding spoofed OIDC discovery documents into the system.

## Recommendation

- Upgrade 9Router to a version containing the patch for CVE-2026-56677.
- Apply authentication middleware to the /api/auth/oidc/test endpoint to ensure only authorized users can trigger outbound requests.
- Implement a network allowlist or blocklist in the application logic to prevent requests to local loopback (127.0.0.0/8) and private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) IP address ranges.
- Validate that the 'issuerUrl' strictly adheres to the 'https://' protocol scheme to prevent protocol smuggling.
- Monitor webserver access logs for anomalous POST requests to the /api/auth/oidc/test endpoint, specifically those originating from external IP addresses.
