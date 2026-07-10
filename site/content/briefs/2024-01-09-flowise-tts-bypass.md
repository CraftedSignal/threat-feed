---
title: Flowise Text-to-Speech API Credit Abuse via Unauthenticated Endpoint
slug: 2024-01-09-flowise-tts-bypass
description: The Flowise text-to-speech generation endpoint is vulnerable to unauthorized access due to accepting arbitrary credential IDs in the request body, enabling attackers to use victim's API keys for services like OpenAI and ElevenLabs, consume their API credits, and generate unlimited speech content at the victim's expense; this affects Flowise versions 3.0.13 and earlier.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - flowise
  - tts
  - api-abuse
  - unauthenticated-access
vendors:
  - Flowise
products:
  - Flowise
references:
  - https://github.com/advisories/GHSA-5fw2-mwhh-9947
rules:
  - title: Detect Flowise Unauthenticated TTS Request
    description: Detects POST requests to the Flowise text-to-speech endpoint without a chatflowId, indicating potential unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    data_sources:
      - webserver
      - linux
  - title: Detect Flowise TTS Request with Credential ID
    description: Detects POST requests to the Flowise text-to-speech endpoint containing a credentialId in the request body.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Flowise is vulnerable to an unauthenticated API credit abuse issue affecting the text-to-speech (TTS) generation endpoint (`/api/v1/text-to-speech/generate`). This vulnerability exists because the endpoint is whitelisted and accepts a `credentialId` directly within the request body. An attacker can exploit this by sending a POST request to the TTS endpoint with a valid `credentialId` obtained from a victim, bypassing authentication checks when the `chatflowId` is not provided. This allows unauthorized use of the victim's linked services such as OpenAI, ElevenLabs, Azure, or Google TTS services, leading to the depletion of API credits and the generation of arbitrary audio content at their cost. The vulnerability impacts Flowise versions up to and including version 3.0.13.

## Attack Chain

1.  Attacker identifies a vulnerable Flowise instance running version 3.0.13 or earlier.
2.  Attacker gains knowledge of a valid `credentialId` associated with a victim's linked TTS service (e.g., OpenAI, ElevenLabs). This might be through exposed API endpoints from a separate finding, or through other means.
3.  Attacker crafts a POST request to `/api/v1/text-to-speech/generate`, omitting the `chatflowId` parameter.
4.  The POST request includes the attacker-controlled `credentialId` in the body along with parameters for `provider`, `voice`, and `model` for the TTS generation.
5.  The vulnerable endpoint processes the request without authentication due to its whitelisted status in `packages/server/src/utils/constants.ts`.
6.  The endpoint utilizes the provided `credentialId` to decrypt and use the stored API key for the specified TTS provider (OpenAI, ElevenLabs, etc.).
7.  The endpoint initiates TTS generation using the victim's API credentials.
8.  The attacker successfully generates speech content, consuming the victim's API credits without authorization, demonstrating abuse of resource-development capabilities.

## Impact

Successful exploitation of this vulnerability allows an attacker to use a victim's API keys (OpenAI, ElevenLabs, Azure, Google) without authorization. This can result in the unauthorized consumption of API credits from the victim's account, potentially incurring significant financial costs. The attacker can generate unlimited speech content at the victim's expense, causing further financial strain and potential disruption of service. When combined with other vulnerabilities that expose credential IDs, the exploitability of this issue is greatly increased.

## Recommendation

*   Apply the suggested fix by removing the TTS endpoint from `WHITELIST_URLS` in `packages/server/src/utils/constants.ts` or implement credential validation to ensure the `credentialId` belongs to the chatflow being used.
*   Monitor web server logs for POST requests to `/api/v1/text-to-speech/generate` without a `chatflowId` parameter as indicated in the rule "Detect Flowise Unauthenticated TTS Request".
*   Review and restrict access to any APIs or endpoints that may expose `credentialId` values to prevent attackers from obtaining valid credentials for this exploit.
