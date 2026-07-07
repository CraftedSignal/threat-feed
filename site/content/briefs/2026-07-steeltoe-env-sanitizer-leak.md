---
title: Steeltoe Environment Actuator Vulnerability (CVE-2026-50200) Leaks Database Passwords
slug: 2026-07-steeltoe-env-sanitizer-leak
description: A high-severity vulnerability, CVE-2026-50200, in the Steeltoe `Sanitizer` component of the Environment actuator allows for the unintended disclosure of sensitive connection string values, including embedded plaintext credentials, when the `/actuator/env` endpoint is accessed, enabling direct database connection and bypassing application-tier security.
date: "2026-07-03T11:22:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - vulnerability
  - .net
  - steeltoe
  - webserver
  - actuator
vendors:
  - Steeltoe
products:
  - Steeltoe.Management.Endpoint <= 4.1.0
  - Steeltoe.Management.EndpointCore <= 3.3.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any caller who can reach `/actuator/env` can receive connection strings containing plaintext credentials.
    confidence_band: high
cves:
  - id: CVE-2026-50200
    cvss: 7.5
    epss: 0.00185
references:
  - https://github.com/advisories/GHSA-q62h-354g-5r85
rules:
  - title: Detects CVE-2026-50200 Exploitation - Access to Steeltoe /actuator/env
    description: Detects CVE-2026-50200 exploitation — HTTP GET requests to the vulnerable /actuator/env endpoint which could lead to sensitive connection string disclosure.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A significant vulnerability, identified as CVE-2026-50200, affects the `Sanitizer` component within the Environment actuator of Steeltoe applications, specifically `Steeltoe.Management.Endpoint` versions `<= 4.1.0` and `Steeltoe.Management.EndpointCore` versions `<= 3.3.0`. This flaw allows sensitive connection string details, including embedded plaintext passwords and user credentials, to be exposed verbatim when the `/actuator/env` endpoint is accessed. The default sanitization rules fail to cover standard .NET `ConnectionStrings:<name>` or Steeltoe Connectors' `Steeltoe:Client:<type>:Default:ConnectionString` patterns. This means that if `env` is exposed in `Management:Endpoints:Actuator:Exposure:Include` on standard deployments, or if accessed by an authenticated Cloud Foundry user with `read_basic_data` permissions via `/cloudfoundryapplication/env`, an attacker can retrieve critical database credentials, leading to direct access to backend databases and circumventing application-level security controls.

## Attack Chain

1.  Attacker conducts reconnaissance to identify a publicly accessible or internally exposed Steeltoe application endpoint, specifically targeting `/actuator/env` or `/cloudfoundryapplication/env`.
2.  The attacker sends an unauthenticated (if publicly exposed) or authenticated (if Cloud Foundry with `read_basic_data` permissions) HTTP GET request to the identified `/actuator/env` or `/cloudfoundryapplication/env` endpoint.
3.  The Steeltoe application's Environment actuator processes the request to display environment properties.
4.  Due to the flaw in the `Sanitizer` component (CVE-2026-50200), configuration keys such as `ConnectionStrings:<name>` or `*:ConnectionString` are not properly redacted.
5.  The application returns the full, unsanitized connection string values, which include plaintext credentials like `Password=` or `user:pass@host`, in the HTTP response body.
6.  The attacker extracts these sensitive database credentials from the response.
7.  Using the obtained credentials, the attacker establishes a direct connection to the backend database.
8.  The attacker can then perform data exfiltration, manipulation, or further persistence actions on the database, bypassing the application layer.

## Impact

Organizations running vulnerable Steeltoe applications are at high risk of credential compromise and direct database access. If successfully exploited, this vulnerability allows attackers to retrieve plaintext database credentials from the `/actuator/env` endpoint. This direct access to databases, such as SQL Server, PostgreSQL, or MySQL, can lead to severe consequences including unauthorized data exfiltration, data tampering, service disruption, and potential lateral movement within the network. The scope of impact is broad, affecting any organization utilizing Steeltoe where the actuator environment endpoint is exposed, either intentionally or inadvertently, without proper sanitization or authorization.

## Recommendation

*   Immediately upgrade `nuget/Steeltoe.Management.Endpoint` to version `4.1.1` or later, and `nuget/Steeltoe.Management.EndpointCore` to version `3.3.1` or later, to patch CVE-2026-50200.
*   If immediate upgrade is not possible, remove `env` from `Management:Endpoints:Actuator:Exposure:Include` in your application configuration to prevent access via the standard path.
*   As a defense-in-depth measure, add `.*connectionstring.*` to the `KeysToSanitize` list in your Steeltoe configuration to ensure these patterns are redacted.
*   Enforce strong authorization on all actuator endpoints to limit access to trusted personnel and systems, as described in the brief's attack chain.
*   Deploy the `Detects CVE-2026-50200 Exploitation - Access to Steeltoe /actuator/env` Sigma rule to your SIEM and tune for legitimate access patterns.
