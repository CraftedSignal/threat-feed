---
title: PraisonAI A2A Server Example Unauthenticated Remote Code Execution
slug: 2026-05-praisonai-a2a-rce
description: 'The PraisonAI A2A server example is vulnerable to remote code execution due to a combination of factors: the example exposes an A2A server without authentication, binds to 0.0.0.0, and registers a `calculate` tool implemented with Python `eval(expression)`.'
date: "2026-05-29T22:32:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - a2a
  - praisonai
  - rce
  - eval
vendors:
  - PraisonAI
products:
  - A2A server example
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-vg22-4gmj-prxw
rules:
  - title: Detect PraisonAI A2A eval Code Execution
    description: Detects code execution via the PraisonAI A2A server example's `calculate` tool and `eval()` function.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI A2A Unauthenticated HTTP Request
    description: Detects unauthenticated HTTP POST requests to the PraisonAI A2A `/a2a` endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The PraisonAI A2A server example combines three critical behaviors, leading to remotely exploitable code execution: the example exposes an A2A server without `auth_token` configuration, binds the server to `0.0.0.0`, and registers a `calculate(expression)` tool implemented with Python `eval(expression)`. An unauthenticated network client can send a JSON-RPC `message/send` request to the `/a2a` endpoint. The A2A handler then passes the attacker-controlled message to `agent.chat()`. When using a real Gemini LLM (`gemini/gemini-2.5-flash-lite`), the model invokes the registered `calculate` tool, causing the `eval()` call to execute arbitrary Python code in the server process. The impact is demonstrated with a canary writing a marker file from an unauthenticated `/a2a` request. This vulnerability is confirmed for the first-party A2A example and deployments following the same pattern of public unauthenticated A2A combined with an unsafe tool.

## Attack Chain

1. An attacker identifies a PraisonAI A2A server instance running the vulnerable example with no authentication configured and bound to `0.0.0.0`.
2. The attacker crafts a JSON-RPC `message/send` request to the `/a2a` endpoint.
3. The A2A server receives the request and passes the message to the `agent.chat()` function.
4. The `agent.chat()` function uses a real LLM (e.g., Gemini) to process the attacker-supplied input.
5. The LLM determines that the `calculate` tool is appropriate for the input.
6. The LLM invokes the `calculate` tool with an expression crafted by the attacker.
7. The `calculate` tool executes the attacker-controlled expression using Python's `eval()` function.
8. The attacker achieves arbitrary Python code execution on the server, potentially leading to data exfiltration, system compromise, or denial of service.

## Impact

The successful exploitation of this vulnerability, as demonstrated in the official example, allows for remote prompt-to-tool execution from an unauthenticated network request. This leads to arbitrary Python execution through the example `calculate()` tool's `eval()`. The compromise of the server process privileges can then expose application files and internal credentials and environment variables. This could result in denial of service or data corruption through executed code.

## Recommendation

- Do not expose A2A servers without authentication. Ensure the `auth_token` is configured correctly to prevent unauthenticated access (reference: `praisonaiagents/ui/a2a/a2a.py`).
- Avoid using `eval()` or similar unsafe functions in registered tools. Implement safe alternatives for calculations and data processing in the `calculate` tool (reference: `examples/python/a2a/a2a-server.py`).
- Review all registered A2A tools to ensure they do not provide unintended access to sensitive data or functionality. Consider implementing a whitelist of allowed functions for the `calculate` tool (reference: `examples/python/a2a/a2a-server.py`).
- Deploy the Sigma rule `Detect PraisonAI A2A eval Code Execution` to identify potential exploitation attempts.
