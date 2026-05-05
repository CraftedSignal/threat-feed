---
title: Langflow Knowledge Bases API Path Traversal Vulnerability
slug: 2024-02-29-langflow-path-traversal
description: A path traversal vulnerability exists in the Langflow Knowledge Bases API (`DELETE /api/v1/knowledge_bases`) that allows an authenticated attacker to delete arbitrary directories on the server's filesystem, leading to data loss and potential service disruption.
date: "2026-05-05T18:28:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - langflow
vendors:
  - pip
products:
  - langflow (<= 1.8.4)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1565
    technique_name: Data Manipulation
references:
  - https://github.com/advisories/GHSA-9whx-c884-c68q
rules:
  - title: Detect Langflow Path Traversal Attempt in DELETE Knowledge Bases API
    description: Detects attempts to exploit the Langflow path traversal vulnerability by monitoring requests to the `DELETE /api/v1/knowledge_bases` endpoint containing path traversal sequences.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
  - title: Detect Langflow rmtree with path traversal
    description: Detects usage of shutil.rmtree with path containing traversal characters.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1565
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Langflow application is susceptible to a critical path traversal vulnerability within its Knowledge Bases API. Specifically, the `DELETE /api/v1/knowledge_bases` endpoint allows authenticated users to delete knowledge bases using the `kb_names` parameter. Due to insufficient sanitization of user-supplied input, an attacker can inject path traversal sequences (e.g., `../`) to manipulate file paths and delete arbitrary directories on the server. This vulnerability affects Langflow versions 1.8.4 and earlier. Successful exploitation can lead to significant data loss, service disruption, and potentially cross-user data compromise if the attacker gains the ability to delete data belonging to other users. Defenders must prioritize patching or mitigating this vulnerability to prevent unauthorized file system modifications.

## Attack Chain

1. An attacker authenticates to the Langflow application.
2. The attacker crafts a malicious request to the `DELETE /api/v1/knowledge_bases` endpoint.
3. The `kb_names` parameter in the request contains a path traversal sequence, such as `../victim_user/kb_name`.
4. The `delete_knowledge_bases_bulk` function in `src/backend/base/langflow/api/v1/knowledge_bases.py` receives the malicious input.
5. The application constructs a file path by directly concatenating the user-supplied `kb_names` parameter without proper sanitization.
6. The `shutil.rmtree()` function is called with the crafted file path, attempting to recursively delete the directory.
7. Due to the path traversal sequence, the deletion occurs outside the intended user directory.
8. Arbitrary directories on the server are deleted, leading to data loss, service disruption, or cross-user data compromise.

## Impact

Successful exploitation of this vulnerability can have severe consequences. An attacker could delete critical system files, causing service disruption. They could also delete other users' knowledge base data, leading to a cross-user data compromise. Because the application has write access, they can traverse to any directory on the entire filesystem accessible to the Langflow service account. The vulnerability impacts any Langflow instance exposing the vulnerable endpoint to authenticated users.

## Recommendation

*   Upgrade Langflow to a version that includes the fix from **PR #12243** and subsequent backports from **PR #12337**.
*   Monitor web server logs for requests to the `DELETE /api/v1/knowledge_bases` endpoint containing path traversal sequences like `../` to detect exploitation attempts. Use the Sigma rule for detection of path traversal attempts.
*   Implement strict input validation and sanitization for all user-supplied parameters, especially those used in file path construction.
