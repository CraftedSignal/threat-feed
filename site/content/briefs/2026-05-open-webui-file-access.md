---
title: Open WebUI Cross-User File Access Vulnerability (CVE-2026-45402)
slug: 2026-05-open-webui-file-access
description: Open WebUI is vulnerable to cross-user file access due to unchecked file_id in Folder Knowledge and Knowledge-Base Attach Endpoints, allowing authenticated users to exfiltrate or overwrite other users' private files given the file UUID (CVE-2026-45402).
date: "2026-05-14T20:31:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - open-webui
  - file-access
  - privilege-escalation
  - cve-2026-45402
products:
  - open-webui (<= 0.9.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-r472-mw7m-967f
  - CVE-2026-45402
rules:
  - title: Detect Open WebUI Knowledge Base File Add
    description: Detects CVE-2026-45402 exploitation — attempt to add a file to a knowledge base using /knowledge/{id}/file/add endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Open WebUI Folder Update with File Injection
    description: Detects CVE-2026-45402 exploitation — attempt to inject a file into folder data using the /folders/{id}/update endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.9.4 and earlier are susceptible to a cross-user file access vulnerability. The vulnerability stems from a lack of proper authorization checks when handling user-supplied `file_id` values in the Folder Knowledge and Knowledge-Base Attach endpoints. An authenticated attacker can exploit this flaw to access and potentially overwrite files belonging to other users by manipulating folder knowledge or attaching malicious files to knowledge bases. The vulnerability was reported on May 14, 2026, and affects systems where Open WebUI is deployed. Exploitation requires knowledge of the victim's file UUID, which, while not directly enumerable, may leak through normal usage patterns, such as chat sources, shared chat citations, URL paths, browser history, and export/share flows.

## Attack Chain

1. The attacker authenticates to the Open WebUI application.
2. The attacker obtains the UUID of a target file belonging to another user through various means, such as shared chats, URL paths, or browser history.
3. The attacker crafts a POST request to the `/api/v1/folders/<attacker_folder_id>/update` endpoint (Path 1) or `/api/v1/knowledge/<kb_id>/file/add` endpoint (Path 2).
4. In Path 1, the attacker includes a `data` payload with a `files` array containing the victim's file UUID, structured as `{"data": {"files": [{"id": "<victim_file_id>", "type": "file"}]}}`.
5. In Path 2, the attacker provides the victim file UUID as the `file_id` parameter in the request body: `{"file_id":"$VICTIM_FILE_ID"}`.
6. If exploiting path 2, the attacker creates a new knowledge base using the /api/v1/knowledge/create endpoint.
7. The server, lacking proper authorization checks on the `file_id`, attaches the victim's file to the attacker's folder or knowledge base.
8. The attacker can then access the victim's file content through RAG flows (Path 1) or the `/api/v1/files/{id}/content` endpoint (Path 2) and, in Path 2, overwrite it using the `/api/v1/files/{id}/data/content/update` endpoint.

## Impact

Successful exploitation of this vulnerability allows any authenticated user to read the contents of any other user's private uploaded file, given knowledge of the file UUID. In the case of Path 2 (knowledge-base attach), the attacker can also overwrite the victim's file content, leading to data tampering and potential misinformation. This can lead to unauthorized data access, data breaches, and integrity compromises. There is no direct availability impact, as the file rows are not deleted.

## Recommendation

- Apply the recommended fix by validating the supplied file_id against the caller's read access before attaching the file in every writer function (backend/open_webui/routers/folders.py, backend/open_webui/routers/knowledge.py).
- Deploy the Sigma rule `Detect Open WebUI Knowledge Base File Add` to detect exploitation attempts targeting the Knowledge-Base Attach endpoint (Path 2).
- Deploy the Sigma rule `Detect Open WebUI Folder Update with File Injection` to detect exploitation attempts targeting the Folder Knowledge ingestion path (Path 1).
- Upgrade to a patched version of Open WebUI that addresses CVE-2026-45402.
