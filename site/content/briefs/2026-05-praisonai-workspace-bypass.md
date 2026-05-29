---
title: PraisonAI Platform Workspace Cross-Access Vulnerability
slug: 2026-05-praisonai-workspace-bypass
description: PraisonAI Platform's workspace-scoped REST routes have an object-level authorization flaw allowing authenticated users from one workspace to access, modify, and delete objects in another workspace by providing the victim object's global UUID.
date: "2026-05-29T22:39:55Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - authorization
  - privilege-escalation
  - workspace-bypass
vendors:
  - PraisonAI
products:
  - PraisonAI Platform
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-6h6v-6m7w-7vxx
rules:
  - title: Detect PraisonAI Platform Cross-Workspace Agent Access
    description: Detects attempts to access agents in different workspaces based on workspace ID and agent ID
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect PraisonAI Platform Cross-Workspace Project Access
    description: Detects attempts to access projects in different workspaces based on workspace ID and project ID
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

PraisonAI Platform is vulnerable to an object-level authorization flaw in its workspace-scoped REST routes. This vulnerability, disclosed on May 29, 2026, allows an authenticated user belonging to one workspace (e.g., `workspace_attacker`) to bypass intended access controls and interact with objects (agents, projects, issues, comments) belonging to another workspace (e.g., `workspace_victim`). The vulnerability stems from the service layer resolving target objects by global UUID without validating workspace membership after initial authorization, leading to a breach of workspace isolation. Successful exploitation enables unauthorized data access, modification, and deletion, impacting data confidentiality, integrity, and availability across different workspaces in the PraisonAI Platform.

## Attack Chain

1.  Attacker creates an account on the PraisonAI Platform.
2.  Attacker logs into the PraisonAI Platform and creates a workspace named `workspace_attacker`.
3.  Victim creates an account on the PraisonAI Platform.
4.  Victim logs into the PraisonAI Platform and creates a workspace named `workspace_victim`.
5.  Victim creates an agent (or project, issue, or comment) within `workspace_victim`, obtaining the global UUID of the object (`victim_agent_id`).
6.  Attacker crafts a request to a workspace-scoped route (e.g., `/api/v1/workspaces/{workspace_attacker}/agents/{victim_agent_id}`) supplying their workspace ID and the victim's object UUID.
7.  The server authenticates the attacker based on their membership in `workspace_attacker`, but retrieves the victim's object from `workspace_victim` using the provided UUID without validating its workspace association.
8.  Attacker reads, modifies, or deletes the victim's object, successfully breaching workspace isolation.

## Impact

Successful exploitation of this vulnerability allows an attacker with access to any workspace to access, modify, and delete data belonging to other workspaces within the PraisonAI Platform. This could lead to unauthorized data breaches, data corruption, and denial of service for legitimate users. The number of affected users and organizations depends on the deployment size of the PraisonAI Platform.

## Recommendation

*   Deploy the Sigma rule `Detect PraisonAI Platform Cross-Workspace Agent Access` to identify attempts to access agents in different workspaces based on workspace ID and agent ID.
*   Deploy the Sigma rule `Detect PraisonAI Platform Cross-Workspace Project Access` to identify attempts to access projects in different workspaces based on workspace ID and project ID.
*   Examine webserver logs for unusual patterns in requests to the agent, project, issue, and comment API routes to detect potential exploitation attempts (logsource: webserver).
