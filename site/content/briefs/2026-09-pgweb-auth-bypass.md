---
title: Authorization Bypass in pgweb API Connect Endpoint
slug: 2026-09-pgweb-auth-bypass
description: An authorization bypass vulnerability in pgweb versions up to 0.17.0 allows unauthenticated attackers to supply arbitrary connection strings via the /api/connect endpoint.
date: "2026-09-15T11:40:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pgweb_project:pgweb:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - authentication-bypass
products:
  - pgweb (<= 0.17.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The pgweb vulnerability allows an unauthenticated attacker to bypass authorization via the /api/connect endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-91924
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91924
rules:
  - title: Detect Potential Exploitation of CVE-2026-91924
    description: Detects unauthorized attempts to POST to the /api/connect endpoint, which may indicate exploitation of the authorization bypass vulnerability.
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
    - action: Inventory all pgweb instances and identify those running version 0.17.0 or earlier.
      owner: IT Operations
      due: 24h
      evidence: Source identified vulnerability in pgweb <= 0.17.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade pgweb to a version released after 0.17.0.
      owner: IT Operations
      addresses: CVE-2026-91924
      evidence: NVD advisory identifies version 0.17.0 as vulnerable.
---

pgweb versions up to and including 0.17.0 contain a critical vulnerability in the POST /api/connect endpoint. When the connect-backend authorization configuration is enabled, the application fails to enforce appropriate access controls. This flaw allows an unauthenticated attacker to supply a custom session identifier and an arbitrary database connection URL. By manipulating these parameters, an attacker can bypass the intended resource-to-database mapping logic and gain unauthorized access to internal database services or other sensitive endpoints that the pgweb instance is capable of reaching. This vulnerability represents a significant risk for environments deploying pgweb as a database management interface, as it effectively allows server-side request forgery (SSRF) and unauthorized data access.

## Impact

Successful exploitation allows an attacker to interact with arbitrary databases, potentially leading to unauthorized data exfiltration, modification, or exposure of sensitive internal infrastructure that would otherwise be shielded by the application's authorization layer. Given the nature of the application, this access often provides a foothold for further lateral movement within internal network segments where database servers are hosted.

## Recommendation

1. Upgrade all instances of pgweb to a version beyond 0.17.0 immediately.
2. Implement network-level access control lists (ACLs) to restrict access to the pgweb /api/connect endpoint to authorized management workstations only.
3. Deploy the provided Sigma rule to monitor for suspicious POST requests to the /api/connect endpoint that deviate from established baselines.
