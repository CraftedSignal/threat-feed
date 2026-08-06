---
title: Authentication Bypass Vulnerability in LettaBot API
slug: 2026-08-lettabot-auth-bypass
description: LettaBot version 0.2.0 contains a missing authentication vulnerability in its API Status Route, enabling remote unauthenticated access to system functions.
date: "2026-08-06T03:21:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - authentication-bypass
  - cve-2026-18990
vendors:
  - letta-ai
products:
  - LettaBot (0.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
cves:
  - id: CVE-2026-18990
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18990
  - https://vuldb.com/cve/CVE-2026-18990
  - https://gist.github.com/YLChen-007/2ba2e586f3d16cb368c8dcd6ef680178
iocs:
  - type: url
    value: https://gist.github.com/YLChen-007/2ba2e586f3d16cb368c8dcd6ef680178
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-18990 Exploitation - Unauthenticated Access to API Status Route
    description: Detects potential exploitation of CVE-2026-18990 by identifying unauthenticated HTTP requests to the LettaBot API Status Route.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rule to monitor and block unauthenticated requests to /api/status on LettaBot instances
      owner: SOC
      due: 24h
      evidence: CVE-2026-18990 description of missing authentication
  mitigation_plan:
    - priority: immediate
      action: Restrict API status endpoint access via network segmentation or firewall
      owner: IT Operations
      addresses: CVE-2026-18990
      evidence: Vulnerability analysis indicates missing auth in LettaBot 0.2.0
---

A security vulnerability (CVE-2026-18990) has been identified in LettaBot version 0.2.0. The flaw resides within the API Status Route, specifically implemented in the file 'src/api/server.ts'. Due to missing authentication checks, remote attackers can interact with this API endpoint without providing valid credentials. This vulnerability is particularly concerning as a public proof-of-concept exploit exists, and the vendor has remained unresponsive to disclosure attempts. Organizations utilizing this specific version of LettaBot are at risk of unauthorized API interaction, potentially leading to information disclosure or further exploitation depending on the capabilities exposed by the status route.

## Attack Chain

1. Attacker performs network reconnaissance to identify internet-facing LettaBot deployments.
2. Attacker probes the API Status Route endpoint (typically associated with src/api/server.ts).
3. Attacker sends a crafted HTTP request to the vulnerable API endpoint.
4. The application fails to validate the requester's identity due to missing authentication logic.
5. The API processes the request and returns status information or executes exposed functions.
6. Attacker leverages the unauthenticated access to exfiltrate system metadata or state information.

## Impact

Successful exploitation allows remote attackers to bypass authentication requirements, potentially leading to unauthorized visibility into the operational status of the LettaBot service. While the full scope of exposed status data depends on the specific deployment, the vulnerability grants attackers an entry point into the application's API layer.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
- Audit all internet-facing instances of LettaBot to determine if they are running version 0.2.0.
- Implement access control lists (ACLs) or network-level restrictions (e.g., VPN, firewall) to limit access to the API Status Route to trusted internal IP ranges.
- Deploy web application firewall (WAF) signatures to detect and block abnormal or unauthenticated requests to the API Status Route endpoint.
- Monitor web server logs for high volumes of requests to API endpoints originating from unauthorized sources.
