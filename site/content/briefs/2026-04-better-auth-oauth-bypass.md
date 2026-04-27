---
title: Better Auth OAuth Provider Authorization Bypass Vulnerability
slug: 2026-04-better-auth-oauth-bypass
description: An authorization bypass vulnerability exists in Better Auth's OAuth provider, allowing low-privilege users to create OAuth clients despite configured clientPrivileges, potentially leading to unauthorized client registration and increased phishing risks.
date: "2026-04-17T12:00:00Z"
severities:
  - high
tags:
  - oauth
  - authorization
  - bypass
  - privilege-escalation
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xr8f-h2gw-9xh6
rules:
  - title: Detect Unauthorized OAuth Client Creation Attempt
    description: Detects attempts to create OAuth clients by users lacking the necessary privileges based on POST requests to the create-client endpoint.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
      - linux
  - title: Detect OAuth Client Creation with Skip Consent
    description: Detects OAuth client creation requests with the skip_consent parameter, which may indicate an attempt to bypass user consent.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An authorization bypass vulnerability affects the OAuth provider component of Better Auth, specifically versions 1.4.8-beta.7 through 1.6.4 and 1.7.0-beta.0 through 1.7.0-beta.1. This flaw allows any authenticated, low-privilege user to create OAuth clients, bypassing the intended restrictions set by the `clientPrivileges` configuration. The vulnerability stems from the client creation endpoints (`adminCreateOAuthClient` and `createOAuthClient`) not enforcing the `clientPrivileges` check before…
