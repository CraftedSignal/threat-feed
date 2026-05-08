---
title: Open WebUI Knowledge Base Destruction and RAG Poisoning via Unauthorized Collection Overwrite
slug: 2024-01-18-open-webui-rag-poisoning
description: Open WebUI is vulnerable to knowledge base destruction and RAG poisoning due to a lack of authorization checks on the `/api/v1/retrieval/process/web` endpoint, allowing an attacker to overwrite a victim's knowledge base with attacker-controlled content.
date: "2024-01-18T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rag
  - poisoning
  - web-application
vendors:
  - pip
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-7r82-qhg4-6wvj
iocs:
  - type: url
    value: https://attacker.com/poison
ioc_counts:
  url: 1
rules:
  - title: Detect Open WebUI Unauthorized Collection Overwrite Attempt
    description: Detects attempts to exploit CVE-2026-44554 by overwriting a knowledge base collection in Open WebUI without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
  - title: Detect Open WebUI Suspicious URL in Retrieval Process
    description: Detects suspicious URLs used in the `/api/v1/retrieval/process/web` endpoint, indicating potential RAG poisoning attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, a retrieval-augmented generation (RAG) application, is susceptible to unauthorized knowledge base modification. The vulnerability lies in the `process_web` endpoint within `backend/open_webui/routers/retrieval.py`. Specifically, the `POST /api/v1/retrieval/process/web` endpoint lacks authorization checks, which allows any authenticated user with knowledge of a target knowledge base UUID to overwrite it with arbitrary content. This is possible due to the `overwrite` parameter, which defaults to `True` and triggers the deletion of the existing vector collection before new content is written via the `save_docs_to_vector_db` function. The issue affects the current main branch (commit `6fdd19bf1`) and likely all versions with RAG functionality. An attacker can leverage this vulnerability to poison the RAG system by injecting malicious content into the knowledge base.

## Attack Chain

1. Attacker gains a valid user account on the Open WebUI instance.
2. Attacker discovers the victim's knowledge base UUID, potentially through the `knowledge-bases` meta-collection (as mentioned in the report).
3. Attacker crafts a POST request to the `/api/v1/retrieval/process/web` endpoint, setting the `collection_name` parameter to the victim's KB UUID and ensures `overwrite=true`.
4. The POST request includes a `url` parameter pointing to an attacker-controlled URL containing malicious content.
5. The Open WebUI server fetches the content from the attacker-controlled URL.
6. The `save_docs_to_vector_db` function is called, which first deletes the existing vector collection associated with the victim's knowledge base.
7. The fetched content from the attacker's URL is then embedded and stored as the new content for the knowledge base.
8. When the victim queries their knowledge base, the RAG system returns the attacker-controlled content, leading to potential misinformation or malicious actions.

## Impact

Successful exploitation leads to data destruction, where the victim's original knowledge base embeddings are permanently deleted from the vector store. Furthermore, the RAG system is poisoned with attacker-controlled content, causing the LLM to return misleading or malicious responses. This can enable indirect prompt injection and manipulation of the victim's LLM behavior. The poisoned content persists until the knowledge base is rebuilt from the original source files, creating a persistent vulnerability. Versions of open-webui up to and including 0.8.12 are affected.

## Recommendation

*   Apply authorization checks to the `/api/v1/retrieval/process/web` endpoint to verify that the user has write access to the target collection, mitigating CVE-2026-44554.
*   Monitor webserver logs for POST requests to `/api/v1/retrieval/process/web` with suspicious `collection_name` parameters, using the Sigma rule "Detect Open WebUI Unauthorized Collection Overwrite Attempt" to identify potential exploitation attempts.
*   Inspect network traffic for connections to suspicious URLs used in the `url` parameter of the `/api/v1/retrieval/process/web` endpoint, such as the IOC `https://attacker.com/poison`.
