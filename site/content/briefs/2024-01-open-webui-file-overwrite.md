---
title: Open WebUI Authenticated File Overwrite Vulnerability (CVE-2026-28788)
slug: 2024-01-open-webui-file-overwrite
description: Open WebUI before version 0.8.6 allows any authenticated user to overwrite arbitrary file content via the `POST /api/v1/retrieval/process/files/batch` endpoint, leading to privilege escalation and potential manipulation of LLM responses.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-28788
  - open-webui
  - file-overwrite
  - privilege-escalation
vendors:
  - Open WebUI
products:
  - Open WebUI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28788
rules:
  - title: Detect Open WebUI File Overwrite Attempt
    description: Detects POST requests to the /api/v1/retrieval/process/files/batch endpoint in Open WebUI, indicating a potential file overwrite attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Open WebUI File UUID Retrieval
    description: Detects GET requests to the /api/v1/knowledge/{id}/files endpoint in Open WebUI, which could be reconnaissance for a file overwrite attack.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Open WebUI is a self-hosted artificial intelligence platform designed for offline operation. A critical vulnerability exists in versions prior to 0.8.6. This vulnerability allows any authenticated user, regardless of their intended privileges, to overwrite the content of any file accessible by the platform. The flaw stems from a lack of ownership checks within the `POST /api/v1/retrieval/process/files/batch` endpoint. This means a standard user with read access to a shared knowledge base can leverage the vulnerability to escalate their privileges and potentially influence the behavior of the language model (LLM). By obtaining file UUIDs and manipulating their content, an attacker can control the information served to the LLM via Retrieval-Augmented Generation (RAG), effectively poisoning the model's responses to other users. Upgrading to version 0.8.6 or later resolves this issue.

## Attack Chain

1. An attacker authenticates to the Open WebUI platform with a standard user account.
2. The attacker identifies a shared knowledge base they have read access to.
3. The attacker sends a `GET` request to `/api/v1/knowledge/{id}/files` to retrieve a list of file UUIDs within the knowledge base.
4. The attacker selects a target file UUID from the list.
5. The attacker crafts a `POST` request to the `/api/v1/retrieval/process/files/batch` endpoint, including the target file UUID and malicious content they wish to inject.
6. The server processes the request without proper ownership or permission checks, overwriting the original file content with the attacker's payload.
7. The LLM, utilizing RAG, now serves the attacker-controlled content to other users who query the knowledge base.
8. The attacker has successfully manipulated the LLM's responses and potentially gained unauthorized control over information dissemination within the platform.

## Impact

Successful exploitation of CVE-2026-28788 allows any authenticated user to overwrite arbitrary files within Open WebUI. This leads to privilege escalation, where a standard user gains write access to files they should only have read access to. More critically, an attacker can manipulate the content served to the LLM via RAG, effectively poisoning the model and providing false or malicious information to other users. This could lead to data breaches, misinformation campaigns, or other security incidents, depending on the content and context of the LLM's usage.

## Recommendation

*   Immediately upgrade Open WebUI to version 0.8.6 or later to patch CVE-2026-28788.
*   Deploy the Sigma rule `Detect Open WebUI File Overwrite Attempt` to monitor for suspicious `POST` requests to the `/api/v1/retrieval/process/files/batch` endpoint.
*   Implement strict file access controls and ownership checks within the Open WebUI platform to prevent unauthorized file modifications.
