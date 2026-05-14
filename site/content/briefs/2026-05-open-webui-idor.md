---
title: Open WebUI IDOR Vulnerability in Retrieval API Allows Unauthorized Access and Modification of Knowledge Bases
slug: 2026-05-open-webui-idor
description: Open WebUI is vulnerable to an IDOR vulnerability in its Retrieval API that bypasses knowledge base access controls, allowing any authenticated user who knows a private knowledge base UUID to read, inject content into, or overwrite another user's knowledge base.
date: "2026-05-14T20:32:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - authorization_bypass
  - data_manipulation
vendors:
  - Open Web UI
products:
  - Open WebUI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Insecure File Storage
references:
  - https://github.com/advisories/GHSA-4g37-7p2c-38r9
rules:
  - title: Detect Open WebUI Unauthorized Knowledge Base Access
    description: Detects unauthorized access to Open WebUI knowledge bases by monitoring API requests to retrieval endpoints with UUID-formatted collection names, indicating a potential IDOR vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
  - title: Detect Open WebUI Knowledge Base Manipulation via Retrieval API
    description: Detects potential manipulation of Open WebUI knowledge bases by monitoring POST requests to `/api/v1/retrieval/process/*` endpoints with UUID-formatted collection names, indicating a potential IDOR vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, a web interface for language models, is vulnerable to an Insecure Direct Object Reference (IDOR) vulnerability in its Retrieval API. This flaw, identified in commit `4d058a125` (v0.8.11) on March 26, 2026, allows authenticated users to bypass knowledge base access controls. Specifically, the `_validate_collection_access` function fails to properly validate access to knowledge base collections, which use UUIDs as collection names. As a result, an attacker who knows the UUID of a private knowledge base can read its contents, inject malicious content, or even overwrite the entire knowledge base through the retrieval query endpoints. This vulnerability exists because the validation function only checks for "user-memory-*" and "file-*" prefixes, leaving knowledge base UUIDs unchecked. This vulnerability is reachable in default configurations, affecting any non-admin account.

## Attack Chain

1.  Attacker obtains an authenticated account on the Open WebUI instance.
2.  Victim user creates a private knowledge base containing sensitive information.
3.  Attacker discovers the UUID of the victim's knowledge base through methods such as shared workspaces, model metadata leakage via the `/api/models/list` endpoint, URL leakage, or RAG citation metadata in shared chats.
4.  Attacker crafts a malicious POST request to `/api/v1/retrieval/query/doc` or `/api/v1/retrieval/query/collection` with the victim's knowledge base UUID as the `collection_name`, bypassing authorization checks and reading the contents of the knowledge base.
5.  Alternatively, the attacker crafts a POST request to `/api/v1/retrieval/process/text` with the victim's knowledge base UUID as the `collection_name` to inject attacker-controlled content into the knowledge base.
6.  Or, the attacker crafts a POST request to `/api/v1/retrieval/process/web` or `/api/v1/retrieval/process/youtube` with the victim's knowledge base UUID as the `collection_name` to overwrite the victim's entire knowledge base.
7.  The injected or replaced content is then used in downstream RAG processes, potentially leading to the exposure of sensitive information or prompt injection attacks.
8.  The attacker successfully compromises the confidentiality, integrity, and availability of the victim's knowledge base.

## Impact

This vulnerability allows unauthorized access to private knowledge bases, potentially exposing sensitive information. Attackers can inject malicious content, leading to integrity breaches and potential prompt injection attacks. The ability to overwrite knowledge bases leads to availability issues and data destruction. A successful attack can compromise the confidentiality, integrity, and availability of user data, potentially affecting all users of the Open WebUI instance.

## Recommendation

*   Deploy the following Sigma rule to detect unauthorized access to knowledge bases by monitoring API requests containing UUID-formatted `collection_name` parameters: `Detect Open WebUI Unauthorized Knowledge Base Access`.
*   Deploy the Sigma rule `Detect Open WebUI Knowledge Base Manipulation via Retrieval API` to identify malicious POST requests to `/api/v1/retrieval/process/*` endpoints with knowledge base UUIDs as `collection_name`.
*   Apply the remediation steps suggested in the original advisory by checking permission on the KB collection in the `_validate_collection_access` function.
*   Monitor web server logs for unusual activity related to the vulnerable endpoints (`/api/v1/retrieval/query/doc`, `/api/v1/retrieval/query/collection`, `/api/v1/retrieval/process/text`, `/api/v1/retrieval/process/web`, `/api/v1/retrieval/process/youtube`, `/api/v1/retrieval/process/file`, `/api/v1/retrieval/process/files/batch`).
