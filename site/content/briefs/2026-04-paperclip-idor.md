---
title: Paperclip Cross-Tenant Agent API Key IDOR Vulnerability
slug: 2026-04-paperclip-idor
description: A Paperclip API vulnerability allows a board user from one company to create, list, and revoke agent API keys in another company, leading to full cross-tenant compromise due to insufficient authorization checks on `/agents/:id/keys` routes.
date: "2026-04-16T22:49:46Z"
severities:
  - critical
tags:
  - idor
  - cross-tenant
  - api
  - paperclip
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Standard Permissions Group Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-3xx2-mqjm-hg9x
rules:
  - title: Detect Paperclip Cross-Tenant API Key Creation
    description: Detects attempts to create agent API keys using the vulnerable Paperclip API endpoint without proper authorization, potentially indicating cross-tenant access attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect Paperclip Cross-Tenant API Access
    description: Detects API requests using an agent token, potentially indicating unauthorized access due to the cross-tenant vulnerability.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect Paperclip Cross-Tenant API Key Enumeration
    description: Detects attempts to list agent API keys using the vulnerable Paperclip API endpoint without proper authorization, potentially revealing sensitive information about other tenants.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.002
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A critical vulnerability exists in the Paperclip control-plane API, specifically in versions prior to 2026.416.0. The vulnerability allows a board user with membership in one company (e.g., Company A) to manipulate agent API keys for agents belonging to a different company (e.g., Company B). This is due to an Insecure Direct Object Reference (IDOR) in the `/agents/:id/keys` routes (GET, POST, DELETE) where the API only validates the user's board-type session but fails to verify access to the…
