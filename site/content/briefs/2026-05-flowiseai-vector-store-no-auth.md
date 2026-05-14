---
title: FlowiseAI OpenAI Assistants Vector Store Missing Authentication
slug: 2026-05-flowiseai-vector-store-no-auth
description: FlowiseAI versions 3.1.1 and earlier are vulnerable to a privilege escalation due to missing authentication and permission checks on the OpenAI Assistants Vector Store CRUD endpoints, allowing any authenticated user to create, modify, upload files to, and delete vector stores and files, regardless of their assigned permissions.
date: "2026-05-14T16:24:56Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - privilege-escalation
  - missing-authentication
  - crud
vendors:
  - FlowiseAI
products:
  - flowise (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-hmg2-jjjx-jcp2
rules:
  - title: Detect FlowiseAI Unauthorized Vector Store Creation
    description: Detects unauthorized creation of vector stores via the /api/v1/openai-assistants-vector-store endpoint in FlowiseAI due to missing permission checks.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1552.006
    data_sources:
      - webserver
  - title: Detect FlowiseAI Unauthorized Vector Store Deletion
    description: Detects unauthorized deletion of vector stores and files via the /api/v1/openai-assistants-vector-store/{id} endpoint in FlowiseAI due to missing permission checks.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1552.006
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI versions up to and including 3.1.1 are vulnerable to a critical privilege escalation issue affecting the OpenAI Assistants Vector Store. The vulnerability stems from a lack of authentication middleware and permission checks on the Create, Read, Update, and Delete (CRUD) endpoints for the vector store. Specifically, the `/api/v1/openai-assistants-vector-store` route, while requiring API key authentication, does not enforce any permission checks on operations. This oversight allows any authenticated user, regardless of their assigned role or permissions, to perform unrestricted actions on the vector store, including creating new stores, uploading files, deleting stores and files, and modifying existing stores.

## Attack Chain

1. An attacker authenticates to the FlowiseAI instance using a valid API key.
2. The attacker sends a POST request to `/api/v1/openai-assistants-vector-store` to create a new vector store.
3. The application, lacking permission checks, creates the new vector store without validating the user's privileges.
4. The attacker sends a POST request to `/api/v1/openai-assistants-vector-store/{id}` to upload malicious files to the created vector store, exploiting the missing checks on file upload.
5. The attacker sends a PUT request to `/api/v1/openai-assistants-vector-store/{id}` to modify the vector store's configuration or data.
6. Alternatively, the attacker sends a DELETE request to `/api/v1/openai-assistants-vector-store/{id}` to delete vector stores and associated files.
7. The application executes the requested operation without proper authorization validation, leading to data manipulation or deletion.

## Impact

Successful exploitation of this vulnerability allows any authenticated user to manipulate OpenAI vector stores within FlowiseAI. This can lead to the upload of malicious files, unauthorized deletion of sensitive data, exfiltration of stored documents, or modification of vector store configurations. This privilege escalation could allow an attacker to compromise the integrity and confidentiality of data stored within FlowiseAI.

## Recommendation

- Deploy the Sigma rule provided below to detect unauthorized creation of vector stores via the `/api/v1/openai-assistants-vector-store` endpoint.
- Deploy the Sigma rule provided below to detect unauthorized deletion of vector stores and files via the `/api/v1/openai-assistants-vector-store/{id}` endpoint.
- Upgrade FlowiseAI to a patched version greater than 3.1.1 to remediate the missing authentication and permission checks.
- Implement robust access control mechanisms and permission validation on all API endpoints to prevent unauthorized data manipulation.
