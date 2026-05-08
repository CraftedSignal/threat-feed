---
title: Open WebUI Model Chaining Access Control Bypass
slug: 2024-01-02-open-webui-model-bypass
description: Open WebUI is vulnerable to an access control bypass due to improper model chaining, allowing a regular user to create a model that chains to a restricted base model and query it using the admin's API key, bypassing access restrictions.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - access-control
  - model-chaining
  - open-webui
  - privilege-escalation
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9vvh-qmjx-p4q8
rules:
  - title: Detect Open WebUI Model Creation with External BaseModelID
    description: Detects Open WebUI model creation requests where the `base_model_id` is set, potentially indicating an attempt to exploit the access control bypass vulnerability (CVE-2026-44555).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Open WebUI Chat Completion Request Using Custom Model with BaseModelID
    description: Detects Open WebUI chat completion requests using a custom model, which has a base_model_id set. This could indicate an attempt to exploit the access control bypass vulnerability (CVE-2026-44555).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, a web interface for Large Language Models, is susceptible to an access control vulnerability via its model chaining feature. This feature allows users to create custom models that reference existing base models for inference. The vulnerability arises because access controls are only applied to the user-facing model, not the chained base model. An attacker with default model creation permissions can exploit this flaw to create a model that chains to a restricted or premium base model, effectively bypassing intended access restrictions and querying the restricted model using the admin-configured API key. This issue affects the current main branch (commit `6fdd19bf1`) and likely all versions with the model chaining feature.

## Attack Chain

1.  Admin provisions a restricted model, such as `gpt-4-turbo-restricted`, and configures access control policies.
2.  Attacker, without access to the restricted model, crafts a `POST` request to `/api/v1/models/create` with a payload defining a new model (e.g., `cheap-assistant`) and setting its `base_model_id` to the restricted model's ID.
3.  The `create` endpoint lacks validation to ensure the attacker has access to the specified `base_model_id`.
4.  The attacker now owns the `cheap-assistant` model, which will pass the initial `check_model_access` check.
5.  The attacker sends a `POST` request to `/api/chat/completions`, specifying the newly created `cheap-assistant` model.
6.  The application resolves the `base_model_id` of `cheap-assistant` to `gpt-4-turbo-restricted` within `main.py:1696`.
7.  The application rewrites the `payload["model"]` to the base model ID, and dispatches the upstream request using the admin-configured API key.
8.  The attacker receives responses from the restricted model, successfully circumventing the intended access restrictions.

## Impact

This vulnerability allows unauthorized access to restricted models, potentially leading to increased costs on pay-per-token backends such as OpenAI or Azure, as the admin's API key is used for unauthorized requests. It also creates a false sense of security, as access restrictions appear to work through the standard model selector but are ineffective against user-created chains. The vulnerability can lead to direct cost impact on pay-per-token backends and erode trust in the configured access controls.

## Recommendation

*   Deploy the Sigma rule `Detect Open WebUI Model Creation with External BaseModelID` to detect attempts to create models with `base_model_id` pointing to existing models, and tune the false positives for your environment.
*   Deploy the Sigma rule `Detect Open WebUI Chat Completion Request Using Custom Model with BaseModelID` to detect chat completion requests using a custom model with a `base_model_id` set.
*   Upgrade to a patched version of Open WebUI that includes proper access control validation for `base_model_id` during model creation to remediate CVE-2026-44555.
