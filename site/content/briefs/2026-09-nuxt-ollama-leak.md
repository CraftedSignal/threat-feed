---
title: Nuxt Ollama API Key Exposure via Public Runtime Configuration
slug: 2026-09-nuxt-ollama-leak
description: The nuxt-ollama module version 1.2.26 inadvertently publishes Ollama cloud API keys in the client-side serialized runtime configuration, allowing unauthorized remote extraction via standard HTTP requests.
date: "2026-09-10T00:51:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-exposure
  - nuxt
  - ollama
  - misconfiguration
vendors:
  - Nuxt
products:
  - nuxt-ollama (1.2.26)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Nuxt's SSR pipeline serializes runtimeConfig.public and embeds it in every server-rendered HTML page for client-side hydration, resulting in the api_key appearing verbatim in the window.__NUXT__ script block.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-fxg7-897c-57mp
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Development Team
  immediate_actions:
    - action: Revoke and rotate any API keys configured in applications utilizing nuxt-ollama.
      owner: Development Team
      due: 24h
      evidence: Source confirms api_key is leaked to plaintext in SSR HTML.
  mitigation_plan:
    - priority: immediate
      action: Modify src/module.ts to migrate api_key from runtimeConfig.public to private runtimeConfig.
      owner: Development Team
      addresses: nuxt-ollama (1.2.26)
      evidence: Recommended remediation provided in GHSA-fxg7-897c-57mp.
---

Nuxt Ollama version 1.2.26 contains a critical design flaw in its module initialization logic that leads to the exposure of sensitive configuration credentials. In the module's setup function, the entire configuration object, including the 'api_key' defined for cloud Ollama usage, is merged into the 'runtimeConfig.public.ollama' namespace. 

Nuxt automatically serializes the public runtime configuration and embeds it into the HTML response of every server-rendered page within the 'window.__NUXT__' object to facilitate client-side hydration. Because the 'api_key' is placed in the public configuration scope, it becomes visible in plaintext within the source code of the web page. Any unauthenticated attacker can retrieve this key by performing a simple HTTP GET request to the application. This vulnerability facilitates unauthorized access to the Ollama cloud API, allowing attackers to consume the operator's billing quotas or potentially access model resources depending on the API key scope.

## Attack Chain

1. The operator configures the application by defining 'api_key' in the Nuxt configuration as documented.
2. The 'nuxt-ollama' module triggers its setup function during the application initialization process.
3. The module merges the 'api_key' into the 'runtimeConfig.public.ollama' object.
4. The Nuxt SSR pipeline serializes the 'runtimeConfig.public' object into an HTML script block.
5. The application serves the rendered HTML containing the plaintext API key to the user browser.
6. The attacker performs an unauthenticated HTTP GET request to the application's base URL.
7. The attacker parses the 'window.__NUXT__' script block in the HTML response to locate the 'api_key' value.
8. The attacker uses the stolen API key to authenticate unauthorized requests to the Ollama cloud API.

## Impact

Successful exploitation allows for the theft of Ollama cloud API keys without requiring any authentication or user interaction. Potential consequences include unauthorized usage of the Ollama cloud API at the operator's expense, rate-limit exhaustion, and potential data exfiltration if the stolen keys have broad scope. As this information is embedded directly into the SSR HTML, the exposure is persistent for all visitors and searchable by web crawlers.

## Recommendation

Prioritized actions for development and security teams:
- Immediately upgrade or patch the implementation to isolate sensitive keys into the private 'runtimeConfig' object rather than 'runtimeConfig.public'.
- Verify existing deployments for the presence of 'api_key' in the 'window.__NUXT__' script block by auditing the source of the home page.
- Revoke any API keys previously configured in applications using version 1.2.26 of the 'nuxt-ollama' module, as these must be considered compromised.
- Implement a move of the 'api_key' logic to server-side utilities (e.g., 'src/runtime/server/utils/useOllama.ts') to ensure it is never exposed to the client-side context.
