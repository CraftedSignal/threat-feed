---
title: Open WebUI Inconsistent Authorization Controls in Memories API
slug: 2026-05-open-webui-authz
description: Open WebUI versions before 0.6.19 have inconsistent authorization controls within the memories API, allowing standard users to view, delete, and restore other users' memories, potentially leading to sensitive data disclosure and unauthorized access as tracked by CVE-2026-44570.
date: "2026-05-11T14:26:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - information-disclosure
  - vulnerability
vendors:
  - Open WebUI
products:
  - open-webui (< 0.6.19)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://github.com/advisories/GHSA-hmjq-crxp-7rjw
  - CVE-2026-44570
rules:
  - title: Detect Unauthorized Memory Query
    description: Detects unauthorized access to memory contents by non-admin users via the /api/v1/memories/query endpoint
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1586
    data_sources:
      - webserver
  - title: Detect Unauthorized Memory Delete
    description: Detects unauthorized deletion of memory contents by non-admin users via the /api/v1/memories/{memory_id} endpoint
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1586
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions prior to 0.6.19 contain an authorization vulnerability in the memories API that allows a standard, non-admin user to perform unauthorized actions on other users' memories. Specifically, a user can view the contents of other users' memories via the `POST /api/v1/memories/query` endpoint, even without having created any memories themselves. Further, the `POST /api/v1/memories/{memory_id}/update` endpoint leaks memory contents even if modification is not permitted. Additionally, the `DELETE /api/v1/memories/{memory_id}` endpoint allows any user to delete existing memories, which can then be restored using the update endpoint. This vulnerability, identified as CVE-2026-44570, allows unauthorized access and modification of sensitive data.

## Attack Chain

1.  Attacker creates a new, non-admin user account on the Open WebUI instance.
2.  Attacker authenticates to obtain a valid JWT bearer token.
3.  Attacker sends a `POST` request to `/api/v1/memories/query` with an empty content payload `{"content": ""}` to enumerate existing memories.
4.  The server responds with memory IDs, content snippets and metadata of other users' memories.
5.  Attacker can then send a `DELETE` request to `/api/v1/memories/{memory_id}` to delete the targeted memory from the application.
6.  Attacker can send a `POST` request to `/api/v1/memories/{memory_id}/update` with an empty content payload `{"content": ""}` to restore a previously deleted memory.
7.  The attacker has now successfully accessed, deleted, and restored data belonging to other users.

## Impact

Successful exploitation of CVE-2026-44570 can lead to the disclosure of sensitive data stored within user memories. Non-admin users can gain unauthorized access to other users' data, delete memories, and restore them. This can impact the confidentiality and integrity of the data managed by Open WebUI. The vulnerability affects Open WebUI instances running versions prior to 0.6.19.

## Recommendation

*   Upgrade Open WebUI to version 0.6.19 or later to patch CVE-2026-44570.
*   Monitor web server logs for unauthorized `POST` requests to `/api/v1/memories/query` originating from non-admin users, looking for anomalous data access patterns.
*   Inspect web server logs for unauthorized `DELETE` requests to `/api/v1/memories/{memory_id}` originating from non-admin users, and correlate with subsequent `POST` requests to `/api/v1/memories/{memory_id}/update`.
*   Deploy the Sigma rule "Detect Unauthorized Memory Query" to identify instances of non-admin users querying the memories API.
