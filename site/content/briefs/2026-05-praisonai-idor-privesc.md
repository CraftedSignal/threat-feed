---
title: PraisonAI Platform Cross-Workspace IDOR and Privilege Escalation
slug: 2026-05-praisonai-idor-privesc
description: PraisonAI Platform is vulnerable to cross-workspace IDOR and member-role privilege escalation, allowing unauthorized users to read, update, or delete resources across workspaces, escalate privileges, and potentially take over accounts and workspaces due to insufficient access controls and role enforcement.
date: "2026-05-29T22:35:47Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - idor
  - privilege-escalation
  - cross-tenant-access
  - fastapi
vendors:
  - PraisonAI
products:
  - praisonai-platform (<= 0.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://github.com/advisories/GHSA-h8q5-cp56-rr65
  - CVE-2026-47407
rules:
  - title: Detect PraisonAI Cross-Workspace Agent Access
    description: Detects unauthorized access to agents in PraisonAI Platform across different workspaces via /api/v1/workspaces/{workspace_id}/agents/{agent_id}.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect PraisonAI Privilege Escalation via Member Role Update
    description: Detects privilege escalation attempts in PraisonAI Platform via PATCH requests to the /workspaces/{workspace_id}/members/{user_id} endpoint, where a member attempts to change their own role or another member's role.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect PraisonAI Open Registration Activity
    description: Detects initial registration requests to the PraisonAI platform's open registration endpoint, which may indicate unauthorized account creation.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 3
---

PraisonAI Platform is susceptible to critical vulnerabilities stemming from insufficient access controls and role enforcement. The platform exposes resources under `/api/v1/workspaces/{workspace_id}/...`, intending to protect them with a `require_workspace_member(workspace_id)` FastAPI dependency. However, this dependency only validates the `workspace_id` in the URL prefix, neglecting to verify the resource's own `workspace_id`. This oversight enables a malicious actor to manipulate the URL, accessing resources across different workspaces. Furthermore, member-management routes lack proper role enforcement, allowing basic members to elevate their privileges to admin or owner. Open registration without email verification at `/api/v1/auth/register` and a default server bind to `0.0.0.0:8000` further exacerbate the risk. Successful exploitation allows attackers to read, update, or delete resources across workspaces, escalate privileges, and potentially take over accounts and workspaces. The vulnerability affects praisonai-platform versions 0.1.2 and earlier.

## Attack Chain

1. An attacker registers an account via the open `/api/v1/auth/register` endpoint to obtain a valid bearer token.
2. The attacker identifies a target workspace ID and a resource ID (agent, issue, project, etc.) within that workspace.
3. The attacker crafts a request to `/api/v1/workspaces/{attacker_workspace_id}/{resource_type}/{target_resource_id}`, substituting `{attacker_workspace_id}` with their own workspace ID and `{target_resource_id}` with the target resource ID.
4. The `require_workspace_member` dependency checks if the attacker is a member of the attacker's workspace, which passes.
5. The service layer retrieves the target resource based solely on the `target_resource_id`, bypassing workspace context validation.
6. The attacker reads, modifies, or deletes the cross-tenant resource. For example, `PATCH /api/v1/workspaces/{attacker_workspace_id}/agents/{target_agent_id}` modifies the target agent's instructions.
7. A low-privileged member uses the `PATCH /{workspace_id}/members/{user_id}` route to promote themself to `admin` due to missing role checks.
8. The attacker deletes the original owner and assumes full control of the workspace.

## Impact

Successful exploitation of these vulnerabilities can have severe consequences. Any registered user can read every agent, issue, project, label, comment, and dependency across all workspaces. Sensitive information such as API keys and connection strings stored within `agent.instructions` and `agent.runtime_config` fields are exposed. Malicious actors can rewrite `agent.instructions` to exfiltrate conversations or manipulate behavior. Additionally, attackers can reassign issues, edit project metadata, and delete critical resources, leading to data loss and service disruption. Basic members can escalate their privileges to admin, evict the owner, and seize control of workspaces. The default deployment configuration exposes the platform to network-based attacks, amplifying the impact of the vulnerability.

## Recommendation

- Apply the suggested fix outlined in the advisory to re-scope every nested-resource lookup to the URL workspace to prevent cross-workspace IDOR vulnerabilities.
- Implement explicit `min_role` arguments on member-management routes to enforce role-based access control and prevent unauthorized privilege escalation.
- Monitor web server logs for suspicious requests to `/api/v1/workspaces/{workspace_id}/agents/{agent_id}` and other nested-resource routes using the provided Sigma rules.
- Deploy the Sigma rule detecting privilege escalation attempts via the `PATCH /{workspace_id}/members/{user_id}` route.
- Block registration from untrusted networks until email verification is implemented.
