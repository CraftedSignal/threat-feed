---
title: Dgraph Unauthenticated Admin Token Disclosure Vulnerability
slug: 2024-01-dgraph-token-disclosure
description: Dgraph versions 25.3.1 and prior expose the admin token via an unauthenticated endpoint, enabling attackers to gain administrative access by reusing the leaked token.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - dgraph
  - credential-disclosure
  - privilege-escalation
  - graphql
vendors:
  - Dgraph
products:
  - Dgraph
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-40173
    cvss: 9.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40173
rules:
  - title: Detect Dgraph Admin Token Access via Debug Endpoint
    description: Detects attempts to access the /debug/pprof/cmdline endpoint in Dgraph, potentially indicating an attempt to retrieve the admin token.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Detect Dgraph Admin Endpoint Access with X-Dgraph-AuthToken
    description: Detects access attempts to sensitive Dgraph admin endpoints using the X-Dgraph-AuthToken header.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Dgraph is an open-source distributed GraphQL database. A critical vulnerability, CVE-2026-40173, affects Dgraph versions 25.3.1 and earlier. The vulnerability stems from the exposure of the `/debug/pprof/cmdline` endpoint on the default mux without requiring authentication. This endpoint discloses the full process command line, including the admin token configured through the `--security "token=..."` startup flag. Successful exploitation allows an attacker to retrieve the leaked token and use it within the `X-Dgraph-AuthToken` header. This bypasses the `adminAuthHandler` token validation, granting unauthorized access to admin-only endpoints such as `/admin/config/cache_mb`. This issue was resolved in Dgraph version 25.3.2. Defenders should prioritize detection and prevention of unauthorized access attempts leveraging this vulnerability.

## Attack Chain

1.  Attacker sends an unauthenticated HTTP GET request to the `/debug/pprof/cmdline` endpoint on the Dgraph Alpha HTTP port.
2.  The Dgraph server responds with the process command line, which includes the admin token configured with the `--security "token=..."` flag.
3.  Attacker extracts the admin token from the command line output.
4.  Attacker crafts an HTTP request to an admin-only endpoint, such as `/admin/config/cache_mb`.
5.  Attacker includes the extracted admin token in the `X-Dgraph-AuthToken` header of the HTTP request.
6.  The Dgraph server receives the request with the forged `X-Dgraph-AuthToken` header.
7.  Due to the vulnerability, the server incorrectly validates the forged token, granting the attacker access to the admin-only endpoint.
8.  Attacker performs unauthorized actions, such as modifying configuration settings or executing operational control functions.

## Impact

Successful exploitation of CVE-2026-40173 allows attackers to gain unauthorized, privileged administrative access to Dgraph deployments. This can lead to unauthorized configuration changes, operational control actions, and potentially complete compromise of the database. The impact is particularly severe in deployments where the Alpha HTTP port is reachable by untrusted parties. There are currently no reports on the number of impacted organizations or specific sectors, but the severity score of 9.4 indicates a high risk of exploitation.

## Recommendation

*   Upgrade Dgraph to version 25.3.2 or later to remediate CVE-2026-40173.
*   Deploy the Sigma rule "Detect Dgraph Admin Token Access via Debug Endpoint" to identify attempts to access the `/debug/pprof/cmdline` endpoint (see rule below).
*   Monitor web server logs for requests to admin-only endpoints with the `X-Dgraph-AuthToken` header to detect exploitation attempts.
*   If upgrading is not immediately feasible, restrict access to the Dgraph Alpha HTTP port to trusted networks or hosts.
