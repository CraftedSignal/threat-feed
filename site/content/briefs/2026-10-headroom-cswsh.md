---
title: Cross-Site WebSocket Hijacking in Headroom
slug: 2026-10-headroom-cswsh
description: The Headroom WebSocket server lacks Origin header validation, enabling Cross-Site WebSocket Hijacking that allows unauthorized parties to perform LLM requests via an injected OpenAI API key.
date: "2026-10-03T04:50:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:headroom_ai:headroom:*:*:*:*:*:*:*:*
vendors:
  - Headroom AI
products:
  - headroom (< 0.35.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker can use a malicious website or browser to initiate unauthorized WebSocket connections to the proxy.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Allowing malicious WebSocket clients to perform arbitrary LLM requests could leverage tools such as the shell tool to perform arbitrary commands leading to RCE.
    confidence_band: high
cves:
  - id: CVE-2026-71416
    cvss: 8.8
    epss: 0.00219
references:
  - https://github.com/advisories/GHSA-h46j-26q3-rggf
  - CVE-2026-71416
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade headroom-ai to version 0.35.0 or later
      owner: IT Operations
      due: 24h
      evidence: GHSA-h46j-26q3-rggf
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to port 8787
      owner: Network Security
      addresses: CVE-2026-71416
      evidence: Vulnerability allows remote connections from browser-based clients
---

The Headroom WebSocket server (pip package `headroom-ai` version < 0.35.0) is vulnerable to Cross-Site WebSocket Hijacking (CSWSH) due to a failure to validate the `Origin` header during the initial WebSocket handshake. By default, the Headroom proxy is configured to facilitate LLM interactions and will automatically inject the `OPENAI_API_KEY` environment variable into the `Authorization` header of outgoing requests if the client fails to provide one.

An attacker can host a malicious webpage that, when visited by a user or headless browser with internal network access to the Headroom proxy, initiates an unauthorized WebSocket connection to `ws://<headroom_host>:8787/v1/responses`. Once established, the attacker can submit arbitrary prompts or tool instructions - such as local shell execution requests - which the proxy will authenticate using the environment-stored API key. This flaw enables unauthenticated remote command execution (RCE) via the proxy's tool-calling capabilities and can result in significant financial loss through quota exhaustion.

## Attack Chain

1. Attacker identifies an accessible instance of a Headroom proxy on an internal network.
2. Attacker hosts a malicious webpage containing a WebSocket client targeting the Headroom proxy at `/v1/responses`.
3. A user within the network visits the malicious webpage via a web browser or a headless browser (e.g., lightpanda).
4. The browser initiates a WebSocket upgrade request to the Headroom proxy; the proxy fails to validate the `Origin` header of the request.
5. The proxy accepts the malicious connection and creates a WebSocket bridge.
6. The attacker sends a `response.create` JSON payload over the socket, including a tool execution command (e.g., `type: "shell"`).
7. Headroom observes the missing `Authorization` header, retrieves the `OPENAI_API_KEY` from the environment, and injects it into the upstream request to OpenAI.
8. The upstream OpenAI API executes the requested tool or prompt, returning the results or triggering RCE in the local environment if shell tools are enabled.

## Impact

Successful exploitation allows for unauthorized LLM model usage, potentially leading to the leakage of proprietary information or sensitive context. More critically, if shell tools or other system-level integrations are enabled in the Headroom configuration, the attacker can achieve remote command execution on the host machine. Furthermore, organizations face the risk of service disruption and financial impact due to the unauthorized consumption of OpenAI API quotas.

## Recommendation

- Upgrade `headroom-ai` to version 0.35.0 or later immediately to incorporate Origin header validation.
- Implement network-level access control to restrict access to the Headroom proxy endpoint (`/v1/responses`) to trusted internal segments only.
- Avoid storing `OPENAI_API_KEY` as a persistent environment variable on servers where the proxy is accessible by untrusted clients; utilize restricted IAM roles or transient credential stores if possible.
- Monitor for unexpected WebSocket connections to the Headroom proxy port (default 8787) originating from client web browsers.
