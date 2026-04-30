---
title: Paperclip Cross-Tenant Agent API Key IDOR Vulnerability
slug: 2026-04-paperclip-idor
description: A Paperclip API vulnerability allows a board user from one company to create, list, and revoke agent API keys in another company, leading to full cross-tenant compromise due to insufficient authorization checks on `/agents/:id/keys` routes.
date: "2026-04-16T22:49:46Z"
type: advisory
types:
  - advisory
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

A critical vulnerability exists in the Paperclip control-plane API, specifically in versions prior to 2026.416.0. The vulnerability allows a board user with membership in one company (e.g., Company A) to manipulate agent API keys for agents belonging to a different company (e.g., Company B). This is due to an Insecure Direct Object Reference (IDOR) in the `/agents/:id/keys` routes (GET, POST, DELETE) where the API only validates the user's board-type session but fails to verify access to the company owning the target agent. By exploiting this flaw, an attacker can mint a new agent API key for an agent in the victim tenant, granting them full agent-level access within that tenant. This cross-tenant compromise allows the attacker to execute workflows, read data, and call any endpoint authorized for agents in the victim tenant, effectively breaching tenant isolation. The vulnerability was introduced due to missing company access checks in the key-management routes.

## Attack Chain

1.  The attacker authenticates as a board user within Company A.
2.  The attacker discovers or obtains the UUID of an agent belonging to Company B.
3.  The attacker sends a POST request to `/agents/<VICTIM_COMPANY_B_AGENT_ID>/keys` with a name to create a new API key.
4.  The server, lacking proper authorization checks, creates a new API key associated with the victim agent's `companyId` and returns the cleartext token.
5.  The attacker uses the newly minted agent token in the `Authorization` header to authenticate subsequent requests.
6.  The server's authentication middleware incorrectly sets the `req.actor` to an agent type associated with the victim's company.
7.  The attacker successfully accesses resources and executes actions within Company B's tenant, bypassing company access checks.
8.  The attacker can enumerate and revoke existing keys using the `/agents/:id/keys` and `/agents/:id/keys/:keyId` endpoints, causing denial of service to legitimate users.

## Impact

This vulnerability leads to a full cross-tenant compromise. An attacker can gain unauthorized access to any tenant within the Paperclip instance, provided they have a minimal valid account (board user in any company) and a victim agent UUID. This allows the attacker to execute workflows, read sensitive data, and call any authorized endpoint within the victim tenant, leading to complete confidentiality, integrity, and availability loss. Furthermore, the attacker can revoke legitimate agent keys, resulting in a denial of service. This represents a scope change, where a vulnerability in Company A's scoping checks results in catastrophic impact within Company B's tenant.

## Recommendation

*   Implement explicit company-access checks on the `/agents/:id/keys` (GET, POST) and `/agents/:id/keys/:keyId` (DELETE) routes before interacting with the service layer. This directly addresses the core issue as described in the advisory's "Recommended Fix" section.
*   Deploy the Sigma rule `Detect Paperclip Cross-Tenant API Key Creation` to identify unauthorized API key creation attempts.
*   Deploy the Sigma rule `Detect Paperclip Cross-Tenant API Access` to detect unauthorized access using stolen agent tokens.
*   Upgrade to npm/@paperclipai/server version 2026.416.0 or later to patch the vulnerability as mentioned in the advisory's "Affected Packages" section.
