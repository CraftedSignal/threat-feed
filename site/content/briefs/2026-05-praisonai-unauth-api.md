---
title: PraisonAI Call Server Unauthenticated Agent Control API
slug: 2026-05-praisonai-unauth-api
description: PraisonAI's call server exposes a network-facing agent control API without authentication when `CALL_SERVER_TOKEN` is not configured, allowing attackers to list, inspect, invoke, and unregister agents due to a fail-open authentication default and a default binding to `0.0.0.0`, as tracked by CVE-2026-47396.
date: "2026-05-29T22:29:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - praisonai
  - unauthenticated-access
  - api
vendors:
  - PraisonAI
products:
  - PraisonAI (<= 4.6.39)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-86qc-r5v2-v6x6
  - CVE-2026-47396
rules:
  - title: Detect PraisonAI Unauthenticated Agent Listing
    description: Detects CVE-2026-47396 exploitation — Unauthenticated HTTP GET request to list PraisonAI agents.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect PraisonAI Unauthenticated Agent Invocation
    description: Detects CVE-2026-47396 exploitation — Unauthenticated HTTP POST request to invoke a PraisonAI agent.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 2
---

PraisonAI's call server is vulnerable to unauthenticated access to its agent control API when the `CALL_SERVER_TOKEN` environment variable is not set. This occurs because the `verify_token()` authentication helper in `praisonai/api/agent_invoke.py` fails open in the absence of the token. The call server is bundled with the vulnerable router and defaults to binding to all interfaces (0.0.0.0). Consequently, operators who launch the call server without setting `CALL_SERVER_TOKEN` risk exposing an unauthenticated remote agent control plane. This vulnerability affects PraisonAI versions up to and including 4.6.39 and is tracked as CVE-2026-47396.

## Attack Chain

1. The PraisonAI call server is started without setting the `CALL_SERVER_TOKEN` environment variable.
2. The `praisonai.api.agent_invoke` router is mounted by `praisonai.api.call`.
3. The call server binds to `0.0.0.0`, making it accessible from any reachable client.
4. An attacker sends an unauthenticated HTTP GET request to `/api/v1/agents` to list registered agents.
5. The attacker retrieves agent metadata and instructions by sending an unauthenticated HTTP GET request to `/api/v1/agents/{agent_id}`.
6. The attacker invokes an agent by sending an unauthenticated HTTP POST request to `/api/v1/agents/{agent_id}/invoke` with a crafted message.
7. The agent executes, potentially triggering downstream tools or external integrations.
8. The attacker unregisters the agent via an unauthenticated HTTP DELETE request to `/api/v1/agents/{agent_id}`, disrupting availability.

## Impact

Running the PraisonAI call server without setting `CALL_SERVER_TOKEN` allows any reachable client to enumerate, inspect, invoke, and unregister agents. This can lead to information disclosure, unauthorized agent execution, consumption of model or API budget, disruption of service, and potentially the execution of privileged actions if agents are connected to external APIs, internal systems, or local tools. The severity depends on the deployed agents and their connected tools. This vulnerability is tracked as CVE-2026-47396.

## Recommendation

*   Set the `CALL_SERVER_TOKEN` environment variable when deploying the PraisonAI call server to enable authentication.
*   Deploy the Sigma rule "Detect PraisonAI Unauthenticated Agent Listing" to detect attempts to list agents without authentication by monitoring HTTP GET requests to `/api/v1/agents`.
*   Deploy the Sigma rule "Detect PraisonAI Unauthenticated Agent Invocation" to detect attempts to invoke agents without authentication by monitoring HTTP POST requests to `/api/v1/agents/{agent_id}/invoke`.
*   Monitor network connections to the PraisonAI call server to identify potentially unauthorized access attempts, especially if the server is exposed to the internet.
