---
title: praisonai-platform IDOR in Dependency Endpoints Allows Cross-Workspace Issue Linking and Deletion
slug: 2026-05-praisonai-idor
description: Praisonai-platform is vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-47406) in its dependency endpoints, allowing an attacker to create, read, or delete dependencies between issues in different workspaces due to missing ownership checks, leading to workflow disruption and information disclosure.
date: "2026-05-29T22:46:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - cross-workspace
  - dependency-injection
  - vulnerability
vendors:
  - praisonai
products:
  - praisonai-platform (<= 0.1.2)
references:
  - https://github.com/advisories/GHSA-4x6r-9v57-3gqw
  - CVE-2026-47406
rules:
  - title: Detect praisonai-platform Cross-Workspace Dependency Creation
    description: Detects CVE-2026-47406 exploitation — Attempts to create dependencies between issues in different workspaces in praisonai-platform based on HTTP POST requests to the dependency endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - webserver
  - title: Detect praisonai-platform Dependency Deletion
    description: Detects CVE-2026-47406 exploitation — Attempts to delete dependencies in praisonai-platform based on HTTP DELETE requests to the dependency endpoint, which may indicate unauthorized manipulation of issue dependencies.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1565.001
    data_sources:
      - webserver
rules_count: 2
---

Praisonai-platform versions 0.1.2 and earlier are vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability in the dependency management endpoints. Specifically, the `POST /workspaces/{workspace_id}/issues/{issue_id}/dependencies` and `DELETE /workspaces/{workspace_id}/issues/{issue_id}/dependencies/{dep_id}` endpoints only check workspace membership, but do not validate that the `issue_id` and `depends_on_issue_id` (in the POST body) belong to the same workspace. This allows an attacker with membership in one workspace to manipulate dependencies across different workspaces, including creating arbitrary links between issues, reading dependency graphs of issues in other workspaces, and deleting legitimate dependencies in other workspaces. The vulnerability stems from a lack of workspace ID validation within the `DependencyService` calls, where raw IDs are used without verification.

## Attack Chain

1.  Attacker obtains valid credentials for a low-privileged user in workspace `W_attacker`.
2.  Attacker identifies issue UUIDs `I1` (in workspace `W_target1`) and `I2` (in workspace `W_target2`) via activity feeds, comments, or other means.
3.  Attacker sends a `POST` request to `/workspaces/W_attacker/issues/I1/dependencies` with the body `{"depends_on_issue_id": "I2", "type": "blocks"}` and valid `Authorization: Bearer <attacker_jwt>`.
4.  The `require_workspace_member` function validates the attacker's membership in `W_attacker`.
5.  The `DependencyService.create(I1, I2, "blocks")` function creates a new `IssueDependency` record linking `I1` and `I2`, without validating that either issue belongs to `W_attacker`.
6.  The UI for workspaces `W_target1` and `W_target2` now reflects the attacker-created dependency. For example, issue `I1` in `W_target1` is shown as "blocked" by `I2` in `W_target2`, disrupting legitimate workflows.
7.  Attacker can list dependencies for arbitrary issues via `GET /workspaces/W_attacker/issues/I1/dependencies`, disclosing information about the project's dependency graph.
8.  Attacker can delete dependencies for arbitrary issues via `DELETE /workspaces/W_attacker/issues/I1/dependencies/{dep_id}`, removing legitimate links and further disrupting project workflows.

## Impact

This vulnerability (CVE-2026-47406) allows an attacker to manipulate issue dependencies across workspaces in praisonai-platform. An attacker can read any issue's dependency graph and create or delete arbitrary links between any two issues, disrupting project workflows and potentially leading to incorrect prioritization or missed dependencies. The most significant impact is the ability to create cross-workspace links, which can affect two foreign workspaces with a single request. This could lead to confusion and wasted effort as teams try to understand and resolve false dependencies.

## Recommendation

*   Apply the suggested fix to `src/praisonai-platform/praisonai_platform/api/routes/dependencies.py` by resolving every issue id (URL and body) against `workspace_id` at the route layer before dispatching to prevent cross-workspace dependency manipulation.
*   Deploy the Sigma rule "Detect praisonai-platform Cross-Workspace Dependency Creation" to identify attempts to create dependencies between issues in different workspaces based on HTTP POST requests to the dependency endpoint.
*   Deploy the Sigma rule "Detect praisonai-platform Dependency Deletion" to identify attempts to delete dependencies using the DELETE request method, which may indicate unauthorized manipulation of issue dependencies.
*   Upgrade praisonai-platform to a version greater than 0.1.2 to remediate CVE-2026-47406.
