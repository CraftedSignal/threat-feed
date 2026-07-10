---
title: OpenStack Keystone LDAP Authentication Bypass Vulnerability (CVE-2026-40683)
slug: 2024-05-keystone-ldap-bypass
description: OpenStack Keystone before 28.0.1 is vulnerable to an authentication bypass due to improper handling of the user enabled attribute in the LDAP identity backend when the user_enabled_invert configuration option is False, leading to disabled users being treated as enabled.
date: "2024-05-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openstack
  - keystone
  - ldap
  - authentication-bypass
vendors:
  - OpenStack
products:
  - Keystone
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-40683
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40683
rules:
  - title: OpenStack Keystone LDAP Authentication Bypass Attempt
    description: Detects successful authentication attempts by users marked as disabled in LDAP due to CVE-2026-40683
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
  - title: OpenStack Keystone LDAP User Enumeration
    description: Detects requests to the Keystone API that may indicate user enumeration attempts via LDAP.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenStack Keystone, a core service providing identity, token, catalog, and policy services in OpenStack clouds, contains an authentication bypass vulnerability (CVE-2026-40683) in versions prior to 28.0.1. The vulnerability lies within the LDAP identity backend, specifically in how it processes the user enabled attribute retrieved from the LDAP server. When the `user_enabled_invert` configuration option is set to False (the default configuration), the `_ldap_res_to_model` method in the `UserApi` class fails to correctly convert the LDAP attribute to a boolean value. This flaw causes users marked as disabled in LDAP to be incorrectly treated as enabled within Keystone, granting them unauthorized access and the ability to perform actions within the OpenStack environment. All deployments using the LDAP identity backend without `user_enabled_invert=True` or `user_enabled_emulation` are susceptible.

## Attack Chain

1. An attacker identifies an OpenStack deployment using Keystone with LDAP authentication and the default `user_enabled_invert=False` configuration.
2. The attacker obtains credentials for a user that is marked as disabled within the LDAP directory.
3. The attacker attempts to authenticate to Keystone using the disabled user's credentials via the standard authentication API endpoint (`/v3/auth/tokens`).
4. Keystone's LDAP backend retrieves the `user_enabled` attribute for the user from the LDAP server.
5. Due to the vulnerability, Keystone incorrectly interprets the "FALSE" string value from LDAP as a truthy value in Python, effectively treating the disabled user as enabled.
6. Keystone generates an authentication token for the user.
7. The attacker uses the authentication token to access other OpenStack services and resources, bypassing the intended access controls.
8. The attacker performs unauthorized actions within the OpenStack environment, such as creating instances, accessing data, or modifying configurations.

## Impact

Successful exploitation of CVE-2026-40683 allows attackers to bypass authentication controls and gain unauthorized access to OpenStack resources. This can lead to a complete compromise of the OpenStack environment, including data breaches, service disruption, and unauthorized resource consumption. The vulnerability affects all OpenStack deployments using the LDAP identity backend with the default configuration, potentially impacting a large number of organizations across various sectors, including cloud service providers, research institutions, and enterprises.

## Recommendation

*   Upgrade OpenStack Keystone to version 28.0.1 or later to patch CVE-2026-40683.
*   As a temporary workaround, set the `user_enabled_invert` configuration option to `True` in the `keystone.conf` file. This will ensure that the user enabled attribute from LDAP is correctly converted to a boolean.
*   Monitor Keystone logs for suspicious authentication attempts, specifically focusing on users marked as disabled in LDAP, and deploy the Sigma rule `OpenStack Keystone LDAP Authentication Bypass Attempt` to identify potential exploitation attempts based on successful authentications of disabled LDAP users.
*   Review and audit user access controls and permissions within the OpenStack environment to minimize the potential impact of unauthorized access.
