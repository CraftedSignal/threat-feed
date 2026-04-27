---
title: Paperclip Cross-Tenant Agent API Token Minting Vulnerability
slug: 2026-04-paperclip-agent-token-minting
description: A vulnerability in Paperclip allows any authenticated user to mint agent API tokens for other tenants, leading to unauthorized access and control due to missing company access checks.
date: "2026-04-17T12:00:00Z"
severities:
  - critical
tags:
  - paperclip
  - broken-access-control
  - cross-tenant
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-47wq-cj9q-wpmp
rules:
  - title: Paperclip Unauthorized Agent Key Creation
    description: Detects unauthorized agent key creation attempts by users without company memberships.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Paperclip Unauthorized Access using Stolen Agent Token
    description: Detects unauthorized access to company data using a stolen agent token.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in Paperclip, specifically affecting instances running in authenticated mode with open sign-ups enabled. This flaw allows any authenticated user, even without any company memberships, to mint API tokens for agents belonging to other companies. This is due to the absence of `assertCompanyAccess` checks on the `/api/agents/:id/keys` endpoint and other agent lifecycle management endpoints. An attacker can exploit this to gain unauthorized access to sensitive…
