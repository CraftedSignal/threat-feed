---
title: Kibana Fleet API Authorization Bypass (CVE-2026-33461)
slug: 2024-01-kibana-auth-bypass
description: Kibana is vulnerable to an authorization bypass (CVE-2026-33461) where users with limited Fleet privileges can access sensitive configuration data, including private keys and authentication tokens, via an internal API endpoint.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kibana
  - authorization-bypass
  - privilege-escalation
vendors:
  - Elastic
products:
  - Kibana
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
cves:
  - id: CVE-2026-33461
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33461
rules:
  - title: Detect Suspicious Kibana Configuration API Access
    description: Detects suspicious access to Kibana configuration API endpoints, potentially indicating CVE-2026-33461 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Kibana API Access Attempt
    description: Detects attempts to access Kibana API endpoints that should only be accessed by administrators.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33461 exposes an incorrect authorization flaw within Kibana's Fleet API. A user possessing limited Fleet privileges can exploit this vulnerability to retrieve sensitive configuration data normally restricted to users with higher-level settings privileges. This is achieved by accessing an internal API endpoint that bypasses the usual authorization checks enforced by dedicated settings APIs. This endpoint directly fetches and returns full configuration objects, failing to properly validate the user's permissions. The vulnerability allows unauthorized access to private keys and authentication tokens, posing a significant risk.

## Attack Chain

1. An attacker with limited Fleet privileges identifies the vulnerable internal API endpoint.
2. The attacker crafts an HTTP request targeting the vulnerable endpoint.
3. The Kibana server receives the request and processes it.
4. Due to the authorization bypass, the server retrieves the full configuration objects without proper permission checks.
5. The server composes a response containing sensitive configuration data, including private keys and authentication tokens.
6. The attacker receives the response containing the unauthorized configuration data.
7. The attacker uses the obtained private keys or authentication tokens to escalate privileges within Kibana or access related systems.
8. The attacker gains unauthorized access to sensitive data or performs administrative actions.

## Impact

Successful exploitation of CVE-2026-33461 allows an attacker with limited privileges to gain unauthorized access to sensitive configuration data within Kibana. This includes private keys and authentication tokens, which can be used to escalate privileges within Kibana or gain access to other systems that rely on these credentials. The impact is significant as it can lead to data breaches, system compromise, and unauthorized administrative actions. The number of affected Kibana installations is currently unknown, but any Kibana instance using the Fleet API is potentially vulnerable.

## Recommendation

*   Upgrade Kibana to a version that addresses CVE-2026-33461 as soon as a patch is available from Elastic.
*   Monitor Kibana access logs (category `webserver`, product `linux` or `windows`) for suspicious requests to internal API endpoints, particularly those related to Fleet configuration. Implement the "Detect Suspicious Kibana Configuration API Access" Sigma rule provided below.
*   Implement the "Detect Unauthorized Kibana API Access Attempt" Sigma rule to detect access attempts from low-privilege users to sensitive API endpoints.
*   Review and enforce strict access control policies within Kibana to limit the privileges of Fleet users to the minimum necessary.
