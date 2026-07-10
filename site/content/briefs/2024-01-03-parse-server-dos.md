---
title: Parse Server Denial of Service via Unindexed Database Query
slug: 2024-01-03-parse-server-dos
description: An unauthenticated attacker can cause a Denial of Service (DoS) by sending authentication requests with arbitrary, unconfigured provider names, leading to a full collection scan on the user database in vulnerable Parse Server versions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - parse-server
  - denial-of-service
  - webserver
vendors:
  - Parse Platform
products:
  - Parse Server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-g4cf-xj29-wqqr
rules:
  - title: Parse Server Authentication Request to Unconfigured Provider
    description: Detects authentication requests targeting unconfigured providers in Parse Server by looking for specific patterns in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Parse Server Excessive Authentication Attempts
    description: Detects an unusually high number of authentication attempts from a single IP address, which could indicate a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in Parse Server, specifically affecting versions greater than or equal to 9.0.0 and less than 9.6.0-alpha.52, as well as versions prior to 8.6.58. The vulnerability stems from the server's behavior when handling authentication requests with unconfigured providers. An unauthenticated attacker can exploit this by sending numerous authentication requests with arbitrary, unconfigured provider names. Before rejecting an authentication request with an unconfigured provider, the server attempts to query the database, resulting in a full collection scan due to the absence of a database index for unconfigured providers. This attack can be parallelized to overwhelm database resources, leading to a denial-of-service condition. The fix involves validating the configuration of authentication providers before initiating any database queries, thus preventing the unnecessary full collection scans.

## Attack Chain

1.  The attacker identifies a vulnerable Parse Server instance running a vulnerable version (>= 9.0.0, < 9.6.0-alpha.52, or < 8.6.58).
2.  The attacker crafts an authentication request targeting an arbitrary, unconfigured authentication provider. This can be achieved by modifying the provider parameter in the authentication API request.
3.  The attacker sends the crafted authentication request to the Parse Server instance's authentication endpoint (e.g., `/parse/users`).
4.  Upon receiving the request, the Parse Server iterates through the available auth providers. If a provider is not configured, the server attempts to query the database for the existence of this provider.
5.  Due to the lack of a database index for unconfigured providers, the database server initiates a full collection scan on the user database for each unconfigured provider in the request.
6.  The attacker floods the server with multiple parallel requests, each targeting a different, unconfigured provider.
7.  The parallel full collection scans overwhelm the database server's resources (CPU, memory, I/O).
8.  The database server becomes unresponsive, leading to a denial-of-service condition affecting the Parse Server and its users.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. The Parse Server becomes unavailable to legitimate users as the database resources are saturated. The number of victims and affected sectors depend on the deployment size and user base of the specific Parse Server instance. If the attack succeeds, the application relying on the Parse Server becomes unusable, potentially leading to financial losses, reputational damage, and disruption of services.

## Recommendation

*   Upgrade Parse Server to a patched version (>= 9.6.0-alpha.52 or >= 8.6.58) to remediate the vulnerability as described in the overview and the advisory (https://github.com/advisories/GHSA-g4cf-xj29-wqqr).
*   Monitor web server logs for unusual authentication requests targeting non-existent authentication providers using the rule `Parse Server Authentication Request to Unconfigured Provider`. Enable webserver logging to activate this rule.
*   Implement rate limiting on the authentication endpoint to mitigate the impact of potential DoS attacks, even after patching. This can be done at the load balancer or web server level.
