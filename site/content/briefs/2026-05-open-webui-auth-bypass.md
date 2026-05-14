---
title: Open WebUI Authorization Bypass Allows Unauthorized File Deletion
slug: 2026-05-open-webui-auth-bypass
description: Open WebUI version 0.8.3 and earlier is vulnerable to an authorization bypass, allowing any authenticated user to permanently delete files owned by other users via `DELETE /api/v1/files/{id}` if the target file is referenced in any shared chat due to a flaw in the `has_access_to_file()` function.
date: "2026-05-14T20:30:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - file-deletion
  - web-application
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Exploitation of Privilege Escalation
references:
  - https://github.com/advisories/GHSA-26g9-27vm-x3q8
  - https://github.com/open-webui/open-webui/blob/main/backend/open_webui/routers/files.py
  - https://github.com/open-webui/open-webui/commit/2e52ad8ff2f8d9ed9f38f76e9bc19c8f92d91fc3
rules:
  - title: Detect Unauthorized Open WebUI File Deletion via Shared Chat Bypass
    description: Detects CVE-2026-45671 exploitation — An authenticated user attempts to delete a file via the API that they do not own but is referenced in a shared chat.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1213
      - T1213.002
    data_sources:
      - webserver
  - title: Detect Open WebUI Knowledge Base File UUID Retrieval
    description: Detects an attempt to retrieve file UUIDs from a knowledge base, which is a prerequisite step for exploiting CVE-2026-45671
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI version 0.8.3 and earlier is vulnerable to an authorization bypass. The vulnerability resides in the `has_access_to_file()` function within `backend/open_webui/routers/files.py`. When a user attempts to delete a file via `DELETE /api/v1/files/{id}`, the function incorrectly authorizes the request if the target file is referenced in any shared chat, regardless of the requesting user's permissions. This occurs because the function checks neither the requesting user's identity nor the type of operation being performed. File UUIDs, which are otherwise difficult to guess, can be obtained by any user with read access to a knowledge base via `GET /api/v1/knowledge/{id}/files`. This vulnerability was tested using a default Docker configuration.

## Attack Chain

1. The attacker authenticates to the Open WebUI application with any valid user account.
2. The attacker identifies a target knowledge base that is shared across multiple users or teams.
3. The attacker sends a `GET /api/v1/knowledge/{kb_id}/files` request to retrieve the file UUIDs associated with the target knowledge base.
4. The attacker selects a file UUID from the list obtained in the previous step, corresponding to a file they do not own.
5. The attacker sends a `GET /api/v1/files/{file_id}/data/content` to confirm the target file is accessible (200 OK).
6. The attacker sends a `DELETE /api/v1/files/{file_id}` request to delete the target file.
7. The `has_access_to_file()` function incorrectly authorizes the deletion because the file is referenced in a shared chat, bypassing permission checks.
8. The server deletes the file from the database, disk, and all knowledge base associations.
9. The attacker verifies permanent deletion by sending a subsequent `GET /api/v1/files/{file_id}/data/content` request, which now returns HTTP 404.

## Impact

This vulnerability can lead to permanent data destruction within Open WebUI deployments. Any multi-user Open WebUI deployment where chat sharing is enabled is affected. An attacker with a valid account can permanently delete files owned by other users, leading to data loss and knowledge base degradation. The delete operation lacks proper auditing, making it difficult to identify the responsible user. The knowledge base will silently lose documents without any user-facing indication that content is missing.

## Recommendation

*   Upgrade to Open WebUI version 0.9.0 or later to apply the fix that addresses the authorization bypass in the `has_access_to_file()` function.
*   Deploy the Sigma rule "Detect Unauthorized Open WebUI File Deletion via Shared Chat Bypass" to monitor for unauthorized file deletion attempts.
*   Restrict access to knowledge bases and shared chats to only authorized users to limit the exposure of file UUIDs.
