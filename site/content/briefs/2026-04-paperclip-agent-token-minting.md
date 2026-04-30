---
title: Paperclip Cross-Tenant Agent API Token Minting Vulnerability
slug: 2026-04-paperclip-agent-token-minting
description: A vulnerability in Paperclip allows any authenticated user to mint agent API tokens for other tenants, leading to unauthorized access and control due to missing company access checks.
date: "2026-04-17T12:00:00Z"
type: advisory
types:
  - advisory
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

A critical vulnerability exists in Paperclip, specifically affecting instances running in authenticated mode with open sign-ups enabled. This flaw allows any authenticated user, even without any company memberships, to mint API tokens for agents belonging to other companies. This is due to the absence of `assertCompanyAccess` checks on the `/api/agents/:id/keys` endpoint and other agent lifecycle management endpoints. An attacker can exploit this to gain unauthorized access to sensitive information within the victim tenant, including company metadata, issues, approvals, agent configurations, and adapter settings. The vulnerability was verified on Paperclip version 2026.411.0-canary.8 (commit b649bd4), which is post the 2026.410.0 patch that addressed a related issue. This vulnerability poses a significant risk to multi-tenant Paperclip deployments.

## Attack Chain

1.  Attacker signs up for a Paperclip account using the default `/api/auth/sign-up/email` endpoint.
2.  Attacker verifies their account and confirms they have no company memberships via `GET /api/companies`.
3.  Attacker identifies the ID of a target agent belonging to a different company, potentially through activity feeds or other exposed APIs.
4.  Attacker sends a `POST` request to `/api/agents/:id/keys` with a desired name for the API key, targeting the victim agent's ID.
5.  The server responds with a `201` status code, returning a plaintext `pcp_*` token. No company access check is performed at this stage.
6.  Attacker uses the stolen token as a `Bearer` credential in subsequent API requests.
7.  The `actorMiddleware` resolves the token to an actor with the victim's company ID, bypassing authorization checks.
8.  Attacker can now access sensitive information such as company metadata, issues, approvals, and agent configurations via API endpoints like `/api/companies/:victimId`, `/api/companies/:victimId/issues`, and `/api/agents/:victimAgentId`. They can also pause, terminate, or delete the agent using other vulnerable endpoints.

## Impact

This vulnerability allows for a complete bypass of tenancy boundaries in Paperclip. The impact includes:

*   **Confidentiality:** Unauthorized access to sensitive company data, including metadata, issues, approvals, agent configurations, and adapter settings.
*   **Integrity:** Ability to manipulate agent configurations and trigger actions within the victim tenant, potentially leading to data breaches or malicious activities.
*   **Availability:** Ability to pause, terminate, or delete agents belonging to other companies, disrupting their operations.

The severity is high due to the ease of exploitation, default configurations, and the persistence of the stolen tokens. The vulnerability affects all Paperclip instances running in `authenticated` mode with open sign-up enabled.

## Recommendation

*   Apply the suggested fix provided in the advisory to `server/src/routes/agents.ts` by implementing company access checks (`assertCompanyAccess`) for the `/api/agents/:id/keys` endpoint.
*   Audit and apply similar fixes to the sibling lifecycle handlers at `/agents/:id/pause`, `/resume`, `/terminate`, and `DELETE /agents/:id` as these share the same vulnerability.
*   Conduct a code-wide sweep for `assertBoard(req)` calls not immediately followed by `assertCompanyAccess` or `assertInstanceAdmin` to identify and address other potential cross-tenant access issues.
*   Deploy the Sigma rules provided below to your SIEM and tune for your environment to detect unauthorized token minting and API access.
*   Monitor Paperclip server logs for unusual API requests to `/api/agents/:id/keys` from users without company memberships.
