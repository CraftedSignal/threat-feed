---
title: PrefectHQ Prefect Authentication Bypass Vulnerability (CVE-2026-7723)
slug: 2024-01-30-prefect-auth-bypass
description: PrefectHQ Prefect versions up to 3.6.13 are vulnerable to an authentication bypass via manipulation of the /api/events/in WebSocket endpoint, potentially allowing remote attackers to execute unauthorized actions.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CVE-2026-7723
  - authentication-bypass
  - websocket
  - prefecthq
vendors:
  - PrefectHQ
products:
  - prefect (<= 3.6.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7723
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7723
rules:
  - title: Detect PrefectHQ Auth Bypass Attempt
    description: Detects suspicious requests to the /api/events/in endpoint that may indicate an authentication bypass attempt in PrefectHQ Prefect.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential PrefectHQ Exploit via WebSocket
    description: Detects potential exploitation attempts against PrefectHQ Prefect by monitoring websocket traffic to the vulnerable endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

PrefectHQ Prefect, a workflow management system, is vulnerable to an authentication bypass vulnerability identified as CVE-2026-7723. The vulnerability exists in versions up to 3.6.13 and stems from a flaw within the `/api/events/in` WebSocket endpoint. A remote attacker can manipulate data sent to this endpoint, leading to a failure in authentication checks. This can allow the attacker to perform unauthorized actions within the Prefect system. The vulnerability was published on 2026-05-04 and a patch is available in version 3.6.14, specifically commit `0d3ab3c2d3f9f98abfafdf7b9f6d4f8ed3925e40`. Defenders should upgrade affected Prefect installations to version 3.6.14 or later to mitigate this risk.

## Attack Chain

1.  Attacker identifies a PrefectHQ Prefect instance running a vulnerable version (<= 3.6.13) with an exposed `/api/events/in` WebSocket endpoint.
2.  The attacker crafts a malicious WebSocket message specifically targeting the `/api/events/in` endpoint.
3.  The attacker sends the manipulated message to the `/api/events/in` endpoint.
4.  Due to the vulnerability, the authentication checks within the WebSocket endpoint fail to properly validate the attacker's identity.
5.  The Prefect system incorrectly processes the attacker's request as authenticated.
6.  The attacker exploits this lack of authentication to execute unauthorized actions within the Prefect system. These actions could include modifying workflows, accessing sensitive data, or disrupting operations.
7.  The attacker may further leverage their access to compromise other connected systems or data stores.

## Impact

Successful exploitation of CVE-2026-7723 allows an unauthenticated remote attacker to bypass authentication mechanisms in PrefectHQ Prefect. This can lead to unauthorized access to sensitive data, modification of workflows, and disruption of critical business processes. The CVSS v3.1 base score is 7.3, indicating a high severity vulnerability. The number of affected organizations depends on the adoption rate of PrefectHQ Prefect, but any organization running a vulnerable version is at risk.

## Recommendation

*   Immediately upgrade PrefectHQ Prefect to version 3.6.14 or later to apply the patch (`0d3ab3c2d3f9f98abfafdf7b9f6d4f8ed3925e40`) that resolves CVE-2026-7723.
*   Monitor web server logs for suspicious activity targeting the `/api/events/in` endpoint to detect potential exploitation attempts. Deploy the Sigma rule `Detect PrefectHQ Auth Bypass Attempt` to identify unusual requests to the vulnerable endpoint.
*   Implement network segmentation to limit the potential impact of a successful exploit by restricting access to sensitive resources from the Prefect server.
