---
title: '@grackle-ai/mcp Workspace Authorization Bypass in knowledge_search MCP Tool'
slug: 2024-02-29-grackle-ai-mcp-auth-bypass
description: The @grackle-ai/mcp package has a workspace authorization bypass vulnerability in its knowledge_search MCP tool that allows scoped agents to bypass workspace isolation and access knowledge graph nodes from other workspaces, leading to cross-workspace data leakage.
date: "2024-02-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - data-leakage
  - workspace-isolation
vendors:
  - Grackle AI
products:
  - '@grackle-ai/mcp'
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://github.com/advisories/GHSA-647h-p824-99w7
rules:
  - title: Detect Unauthorized Workspace ID in knowledge_search Request
    description: Detects requests to the knowledge_search handler with a workspaceId that differs from the agent's assigned workspace.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Workspace ID in knowledge_get_node Request
    description: Detects requests to the knowledge_get_node handler with a workspaceId that differs from the agent's assigned workspace.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `@grackle-ai/mcp` package, specifically versions 0.70.1 and earlier, contains a critical authorization bypass vulnerability within the `knowledge_search` and `knowledge_get_node` MCP tools. This vulnerability allows scoped agents operating within one workspace to circumvent intended isolation boundaries and access knowledge graph nodes residing in other workspaces. This is due to the `knowledge_search` and `knowledge_get_node` handlers failing to properly receive or enforce workspace scoping via the `authContext`. This vulnerability poses a significant risk of cross-workspace data leakage in deployments where multiple workspaces contain sensitive knowledge graph data and scoped agents are utilized. The issue was reported on March 25, 2026, and is tracked as GHSA-647h-p824-99w7. Defenders should prioritize patching or implementing workarounds to mitigate this risk.

## Attack Chain

1. A scoped agent is deployed within Workspace A, possessing limited permissions within that workspace.
2. The attacker identifies the presence of the `knowledge_search` and `knowledge_get_node` tools within the `SCOPED_TOOLS` set, indicating their accessibility to scoped agents.
3. The attacker crafts a request to the `knowledge_search` or `knowledge_get_node` handler, supplying an arbitrary `workspaceId` parameter corresponding to Workspace B.
4. Due to the missing `authContext` and lack of workspace scoping enforcement in the handler, the request bypasses intended access controls.
5. The handler retrieves knowledge graph nodes from Workspace B based on the attacker-supplied `workspaceId`.
6. The data from Workspace B is returned to the scoped agent in Workspace A.
7. The attacker gains unauthorized access to sensitive knowledge graph data residing in Workspace B.
8. The attacker can exfiltrate or misuse the compromised data, leading to data leakage or other malicious activities.

## Impact

This vulnerability results in cross-workspace data leakage, potentially exposing sensitive information stored in knowledge graphs across different workspaces. The number of affected deployments depends on the adoption rate of `@grackle-ai/mcp` with scoped agents and multi-workspace configurations. Successful exploitation can lead to unauthorized access to confidential data, impacting data privacy, compliance, and potentially causing reputational damage. The vulnerability affects any deployment where multiple workspaces contain sensitive knowledge graph data and scoped agents are used, putting organizations at significant risk.

## Recommendation

*   Upgrade `@grackle-ai/mcp` to a patched version beyond 0.70.1 to address the authorization bypass vulnerability.
*   As a temporary workaround, remove `knowledge_search` and `knowledge_get_node` from the `SCOPED_TOOLS` set in `tool-scoping.ts` to restrict access to these tools for scoped agents.
*   Monitor the usage of `knowledge_search` and `knowledge_get_node` handlers for requests originating from scoped agents, and alert on any attempts to access knowledge graph nodes from different workspaces.
*   If scoped agents are not currently used in multi-workspace deployments, consider disabling them temporarily until the patch is applied.
