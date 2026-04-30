---
title: Dgraph Unauthenticated Admin Token Disclosure via /debug/vars
slug: 2024-05-dgraph-auth-bypass
description: Dgraph versions prior to 25.3.3 expose the admin token via the `/debug/vars` endpoint, allowing unauthenticated attackers to bypass authentication and gain administrative access.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - dgraph
  - authentication-bypass
  - admin-token-disclosure
vendors:
  - Dgraph
products:
  - Dgraph
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-vvf7-6rmr-m29q
rules:
  - title: Detect Access to Dgraph /debug/vars Endpoint
    description: Detects unauthorized access attempts to the /debug/vars endpoint, which can expose sensitive information.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Detect Dgraph Admin Endpoint Access with Auth Token
    description: Detects access to the /admin/config/cache_mb endpoint with a specified X-Dgraph-AuthToken header, potentially indicating unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Detect Dgraph /debug/vars Access Followed by Admin Endpoint Use
    description: Detects a sequence of events where the /debug/vars endpoint is accessed, followed by the use of an admin endpoint with the X-Dgraph-AuthToken header. This combination suggests potential exploitation of the admin token disclosure vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Dgraph, a graph database, exposes sensitive information through an unauthenticated endpoint, `/debug/vars`, in versions prior to 25.3.3. The vulnerability arises because the admin token is often passed as a command-line argument using the `--security "token=..."` flag. This argument is exposed through the `/debug/vars` endpoint, which is enabled by default via Go's `expvar` package. An attacker can retrieve this token without authentication and then use it to gain administrative privileges by including it in the `X-Dgraph-AuthToken` header of subsequent requests. This is a bypass of previous attempts to mitigate similar issues via `/debug/pprof/cmdline`, which were addressed incompletely. This issue impacts deployments where the Alpha HTTP port is reachable by untrusted parties, allowing for a full authentication bypass.

## Attack Chain

1. An attacker sends an unauthenticated GET request to the `/debug/vars` endpoint on the Dgraph Alpha server (e.g., `GET /debug/vars HTTP/1.1`).
2. The server responds with a JSON payload containing the `cmdline` field.
3. The attacker parses the JSON response and extracts the value of the `cmdline` field.
4. The attacker searches the `cmdline` output for the `--security token=...` argument.
5. The attacker extracts the admin token from the `--security` argument string.
6. The attacker sends a request to an admin-only endpoint (e.g., `GET /admin/config/cache_mb HTTP/1.1`).
7. The attacker includes the extracted admin token in the `X-Dgraph-AuthToken` header of the request.
8. The Dgraph Alpha server validates the token, granting the attacker administrative access.

## Impact

Successful exploitation allows an unauthenticated attacker to gain complete administrative control over the Dgraph database. This includes the ability to read and modify admin configurations, and perform operational control actions. In deployments where the Alpha HTTP port is publicly accessible, this vulnerability poses a significant risk, leading to potential data breaches, service disruption, and unauthorized manipulation of the database. While the number of affected deployments is not explicitly stated, any Dgraph instance running a vulnerable version with an exposed Alpha HTTP port is at risk.

## Recommendation

*   Upgrade Dgraph to version 25.3.3 or later to address the vulnerability.
*   As a temporary workaround, restrict access to the Alpha HTTP port to trusted networks only.
*   Deploy the Sigma rule below to detect unauthorized access attempts to the `/admin/config/cache_mb` endpoint using the `X-Dgraph-AuthToken` header.
*   Deploy the Sigma rule below to detect access to `/debug/vars` endpoint.
