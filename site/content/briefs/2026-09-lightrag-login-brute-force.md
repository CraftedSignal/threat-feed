---
title: Unauthenticated Brute-Force Vulnerability in LightRAG-HKU
slug: 2026-09-lightrag-login-brute-force
description: The /login endpoint in LightRAG-HKU versions prior to 1.5.5 lacks rate limiting or account lockout, enabling high-speed credential brute-force attacks.
date: "2026-09-23T01:54:20Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:lightrag-hku:lightrag-hku:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication
  - web-application
vendors:
  - LightRAG-HKU
products:
  - lightrag-hku (< 1.5.5)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: The POST /login endpoint has no rate limiting, account lockout, or delay on failed attempts.
    confidence_band: high
cves:
  - id: CVE-2026-85734
    cvss: 9.1
references:
  - https://github.com/advisories/GHSA-frch-4w6v-q5xx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85734
rules:
  - title: Detect Excessive Login Attempts to LightRAG-HKU
    description: Detects potential brute-force attempts against the /login endpoint by counting high volumes of 401 status responses from a single source.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade LightRAG-HKU to version 1.5.5 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-85734
  enrichment_needed:
    - item: Verify current version of LightRAG-HKU deployed in production.
      owner: SOC
      reason: Determine scope of vulnerability
      evidence: CVE-2026-85734
  hunt_leads:
    - lead: Search logs for high volumes of 401 status codes targeting /login.
      technique_id: T1110.001
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly mentions lack of rate limiting on /login endpoint.
  mitigation_plan:
    - priority: immediate
      action: Patch LightRAG-HKU to version 1.5.5.
      owner: IT Operations
      addresses: CVE-2026-85734
      evidence: Source advisory confirms patch availability.
---

LightRAG-HKU, a framework for knowledge graph retrieval, contains a critical security flaw in its authentication mechanism. The application's `/login` endpoint, implemented in `lightrag/api/lightrag_server.py`, fails to implement rate limiting, account lockout, or request delays for failed authentication attempts. This oversight allows an unauthenticated, network-reachable attacker to programmatically iterate through password lists at full network speed to compromise administrative or user accounts. The vulnerability, tracked as CVE-2026-85734, affects all versions prior to 1.5.5. Given the sensitivity of the data stored within LightRAG knowledge graphs, successful exploitation provides unauthorized access to proprietary documents and administrative operations.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable instances of LightRAG-HKU on default port 9621.
2. Attacker interacts with the target HTTP service to confirm the presence of the `/login` endpoint.
3. Attacker prepares a dictionary of common passwords or credential lists for brute-force operations.
4. Attacker writes a script to automate HTTP POST requests to the `/login` endpoint.
5. Attacker executes the script, passing user credentials via `form_data` without encountering server-side throttling.
6. Attacker monitors the HTTP response codes (e.g., waiting for a 200 OK) to identify successful password matches.
7. Attacker uses the compromised credentials to access the LightRAG API and extract sensitive knowledge graph information.

## Impact

Successful exploitation allows for full unauthorized access to the LightRAG instance. Depending on the deployment, this could lead to the exposure of confidential knowledge stored in the graph, unauthorized administrative changes, and full exfiltration of sensitive data processed by the application.

## Recommendation

* Update LightRAG-HKU to version 1.5.5 or later immediately to patch CVE-2026-85734.
* Implement external rate limiting or a Web Application Firewall (WAF) in front of the LightRAG-HKU service to detect and block high-frequency POST requests to the `/login` endpoint.
* Monitor web server logs for anomalous patterns of 401 Unauthorized status codes from single IP addresses directed at the `/login` endpoint.
