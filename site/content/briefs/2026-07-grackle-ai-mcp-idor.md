---
title: Grackle AI MCP Tool Layer Fail-Open Authorization Leads to IDOR and Privilege Escalation (GHSA-f9ff-5x35-7gfw)
slug: 2026-07-grackle-ai-mcp-idor
description: The Grackle AI MCP tool layer, specifically versions of `@grackle-ai/mcp`, `@grackle-ai/plugin-core`, and `@grackle-ai/auth` up to `0.132.1`, suffers from an authorization bypass (IDOR) due to inconsistent inline checks, allowing a compromised scoped agent to perform unauthorized cross-task and cross-session operations, leading to data manipulation, denial of service, and sensitive data disclosure across workspaces.
date: "2026-07-03T11:35:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - authorization-bypass
  - privilege-escalation
  - denial-of-service
  - code-vulnerability
  - software-component
vendors:
  - Grackle AI
products:
  - '@grackle-ai/mcp (<= 0.132.1)'
  - '@grackle-ai/plugin-core (<= 0.132.1)'
  - '@grackle-ai/auth (<= 0.132.1)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A malicious or prompt-injected scoped agent can therefore perform cross-task and cross-session operations it should not be allowed to (an IDOR / privilege-boundary bypass).
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Exploit: cross-session SIGKILL DoS against a sibling agent or the root orchestrator; foreign session resume.'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'Exploit: a malicious agent in a workspaceless session calls task_list (no args) → reads every task in every workspace, then task_show {taskId} cross-workspace (title/description/branch/review-notes).'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f9ff-5x35-7gfw
---

Grackle AI's Multi-Agent Collaboration Protocol (MCP) tool layer, including `@grackle-ai/mcp`, `@grackle-ai/plugin-core`, and `@grackle-ai/auth` up to version `0.132.1`, contains critical authorization bypass vulnerabilities (GHSA-f9ff-5x35-7gfw). The core issue stems from inconsistent inline authorization checks within the tool layer, which is the *sole* authorization boundary for scoped callers. Because the MCP server authenticates all outbound gRPC with a full server API key and backend gRPC handlers perform no caller-based authorization, several mutating tools (`task_update`, `task_delete`, `task_resume`, `session_kill`, `session_resume`) silently omit necessary ancestry/workspace checks, effectively "failing open." This allows a malicious or prompt-injected scoped agent to perform unauthorized cross-task and cross-session operations, enabling IDOR, privilege escalation, and denial of service. Additionally, a flaw in handling workspaceless sessions allows for cross-workspace read-only data disclosure. The vulnerability was published on July 2, 2026.

## Attack Chain

1.  **Initial Access/Compromise**: An attacker gains control over an existing Grackle AI "scoped agent" within a customer environment, potentially through prompt injection, misconfiguration, or compromising the underlying system hosting the agent.
2.  **Task ID Enumeration (F2)**: The compromised scoped agent leverages legitimate tools like `task_list` or `task_search` to discover `taskId` values belonging to other tasks, including those of sibling agents, parent tasks, or tasks in different workspaces.
3.  **Cross-Workspace Discovery (F7)**: If the compromised agent operates from a workspaceless session, it exploits the `workspaceId: undefined` bypass in `mcp-server.ts` to call `task_list` (without arguments) and retrieve information about *all* tasks across *all* workspaces within the Grackle AI instance.
4.  **Unauthorized Data Disclosure (F7)**: Using the enumerated `taskId` values, the agent then calls `task_show {taskId}` or `schedule_show` to access and potentially exfiltrate sensitive details (e.g., title, description, branch, review notes) from tasks it is not authorized to view across workspaces.
5.  **Task Data Manipulation/Destruction (F2)**: The agent invokes `task_update`, `task_delete`, or `task_resume` with arbitrary `taskId` values (bypassing ancestry checks), allowing it to modify (e.g., change status to `complete`/`failed`, rewrite dependency DAG/budgets) or permanently delete tasks belonging to other agents or the human orchestrator.
6.  **Session Denial of Service / Hijacking (F6)**: The agent calls `session_kill {sessionId}` or `session_resume {sessionId}` (bypassing ancestry checks) to terminate or resume active sessions of other agents or the root orchestrator, leading to a denial of service or unauthorized session control.

## Impact

The vulnerabilities allow a compromised Grackle AI scoped agent to escalate privileges, gain unauthorized access to sensitive data, and disrupt operations. Specifically, attackers can permanently destroy other agents' or the human orchestrator's work, corrupt task dependency graphs and budgets, terminate other active sessions (leading to a denial of service for sibling agents or the root orchestrator), hijack foreign sessions, and exfiltrate sensitive task metadata (titles, descriptions, branch info, review notes) from any workspace. The "fail-open" nature means new tools can introduce similar vulnerabilities if ancestry checks are omitted, making the system inherently fragile. The advisory covers systemic findings F2, F6, F7, and F12.

## Recommendation

*   Prioritize updating all `@grackle-ai/mcp`, `@grackle-ai/plugin-core`, and `@grackle-ai/auth` packages to versions *greater than* `0.132.1` to address GHSA-f9ff-5x35-7gfw.
*   Ensure that the remediation for GHSA-f9ff-5x35-7gfw, specifically the enforcement of scope centrally in the `CallToolRequest` dispatcher (`mcp-server.ts`) via `targetTaskIdArg` / `targetSessionIdArg` descriptors, is fully implemented and operational.
*   Verify that `assertCallerIsAncestor` or equivalent self-or-ancestor checks have been added to `task_update`, `task_delete`, `task_resume`, `session_kill`, and `session_resume` as described in the remediation for GHSA-f9ff-5x35-7gfw.
*   Confirm that the fix for F7, preventing failure-open on empty `workspaceId` and applying `task_show` membership checks for all scoped non-root callers, is properly deployed per GHSA-f9ff-5x35-7gfw.
*   If `scoped-token.ts` (F12) is wired into task-abort/stop flows with SQLite-backed persistence, ensure this feature is functional to allow for proper scoped token revocation, as recommended in GHSA-f9ff-5x35-7gfw.
