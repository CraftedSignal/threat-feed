---
title: Open WebUI /responses Endpoint Authentication Bypass Vulnerability
slug: 2024-01-open-webui-auth-bypass
description: The /responses endpoint in Open WebUI's OpenAI router lacks access control, allowing authenticated users to bypass per-model access controls and interact with any configured model, potentially leading to denial of service, model theft, and access policy bypass.
date: "2026-05-08T19:45:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - llm
  - owasp
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.8.12)
references:
  - https://github.com/advisories/GHSA-hp5m-24vp-vq2q
  - https://github.com/open-webui/open-webui/pull/23481
rules:
  - title: Detect Open WebUI Unauthorized Model Access via Responses Endpoint
    description: Detects CVE-2026-44556 exploitation — unauthorized access to models via the /responses endpoint in Open WebUI
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Open WebUI Expensive Model Access via Responses Endpoint
    description: Detects CVE-2026-44556 exploitation — suspicious access to expensive models (e.g., gpt-4) via the /responses endpoint in Open WebUI
    platform: sigma
    severity: medium
    tactics:
      - resource_hijacking
    techniques:
      - T1496
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.8.12 and earlier contain an authentication bypass vulnerability in the /responses endpoint of the OpenAI router. This endpoint, intended as a proxy to upstream LLM providers, fails to enforce per-model access controls. While the primary chat completion endpoint (generate_chat_completion) correctly validates model ownership, group membership, and AccessGrants, the /responses endpoint only verifies a valid user session. Consequently, any authenticated user can interact with any model configured on the Open WebUI instance, regardless of their assigned roles or group memberships, by sending a crafted POST request to /api/openai/responses with an arbitrary model ID. This circumvents intended access restrictions and poses risks to service availability, model security, and policy enforcement.

## Attack Chain

1. An attacker obtains valid user credentials for the Open WebUI instance. This could be through credential stuffing, phishing, or other common methods.
2. The attacker authenticates to the Open WebUI instance using the obtained credentials.
3. The attacker crafts a POST request to the `/api/openai/responses` endpoint.
4. The attacker includes an arbitrary model ID in the POST request body, specifying a model they do not have explicit access to under normal access control policies.
5. The Open WebUI instance, upon receiving the request at `/api/openai/responses`, only verifies the user's session.
6. Due to the missing access control checks, the request is forwarded to the upstream LLM provider, effectively bypassing the intended access restrictions.
7. The upstream LLM provider processes the request using the specified model, even though the user lacks authorization.
8. The attacker receives the response from the LLM, successfully interacting with a restricted model.

## Impact

Successful exploitation of this vulnerability can have significant consequences. Unauthorized users can submit resource-intensive requests to expensive models, leading to Model Denial of Service (OWASP LLM04) by exhausting API budgets or rate limits, potentially causing total service disruption for legitimate users. Furthermore, if the instance proxies access to fine-tuned or self-hosted models, unauthorized interaction can lead to Model Theft (OWASP LLM10), enabling capability extraction or model distillation. Finally, the vulnerability undermines existing access control systems, preventing administrators from enforcing cost-tier restrictions, team-based model assignments, or compliance boundaries.

## Recommendation

*   Upgrade to Open WebUI version 0.8.13 or later to patch CVE-2026-44556 and address the authentication bypass vulnerability.
*   Deploy the Sigma rule "Detect Open WebUI Unauthorized Model Access via Responses Endpoint" to identify potential exploitation attempts by monitoring POST requests to `/api/openai/responses` with potentially malicious model IDs.
*   Review Open WebUI access logs for any suspicious activity related to the `/api/openai/responses` endpoint, particularly requests from users who should not have access to specific models.
