---
title: Keycloak OIDC Implicit Flow Bypass Vulnerability (CVE-2026-7571)
slug: 2026-05-keycloak-oidc-bypass
description: CVE-2026-7571 describes a vulnerability in Keycloak where a low-privilege user can bypass security controls intended to disable the implicit flow in OpenID Connect (OIDC) clients by manipulating client data during session restart, potentially exposing access tokens.
date: "2026-05-19T12:18:22Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - keycloak
  - oidc
  - implicit-flow
  - cve-2026-7571
  - credential-access
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-7571
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7571
rules:
  - title: Detect Keycloak OIDC Implicit Flow Bypass Attempt
    description: Detects CVE-2026-7571 exploitation attempts by monitoring for suspicious client data manipulation patterns during Keycloak OIDC session restarts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Keycloak Admin Console Access from Uncommon IPs
    description: Detects access to the Keycloak admin console from IP addresses not commonly associated with administrative activity.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-7571 describes a flaw in Red Hat Keycloak, an open-source identity and access management solution. This vulnerability allows a low-privilege user, who possesses valid user credentials and knowledge of the client ID, to bypass security controls designed to disable the implicit flow in OpenID Connect (OIDC) clients. The vulnerability arises from improper handling of client data during a session restart. By manipulating this data, a malicious user can trick the system into issuing an access token that should otherwise be unavailable. This can lead to unauthorized access and privilege escalation within applications relying on Keycloak for authentication and authorization. Furthermore, the exposure of these access tokens in server logs, proxy logs, and HTTP Referrer headers can result in sensitive information disclosure.

## Attack Chain

1. An attacker obtains valid user credentials for a low-privilege account managed by Keycloak.
2. The attacker identifies a client ID configured within Keycloak for an OIDC application.
3. The attacker initiates an authentication request to the OIDC client, triggering a session within Keycloak.
4. During the session restart or renewal process, the attacker manipulates the client data being transmitted to Keycloak.
5. The attacker bypasses the intended restrictions on the implicit flow by altering the client data.
6. Keycloak, due to the manipulated client data, incorrectly issues an access token to the attacker.
7. The attacker uses the unauthorized access token to access protected resources of the OIDC application.
8. The access token may be logged by the server, proxy, or included in HTTP Referrer headers, potentially leading to exposure of sensitive data.

## Impact

Successful exploitation of CVE-2026-7571 can lead to unauthorized access to protected resources and privilege escalation within applications secured by Keycloak. This can result in data breaches, account compromise, and other security incidents. The exposure of access tokens in logs and headers further exacerbates the risk, potentially allowing attackers to gain persistent access to sensitive information. The impact is heightened in environments where Keycloak is used to manage access to critical systems and data.

## Recommendation

*   Apply the latest security patches released by Red Hat for Keycloak to address CVE-2026-7571.
*   Implement the Sigma rule `Detect Keycloak OIDC Implicit Flow Bypass Attempt` to detect potential exploitation attempts by monitoring for suspicious client data manipulation during session restarts.
*   Enable verbose logging on Keycloak and related infrastructure components (proxies, web servers) to capture relevant events for incident investigation.
*   Review and restrict access to Keycloak server logs and proxy logs to prevent unauthorized exposure of access tokens.
*   Implement security policies that discourage the storage of sensitive information in HTTP Referrer headers.
