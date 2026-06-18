---
title: npm PraisonAI AgentOS Unauthenticated API Exposure
slug: 2026-06-npm-praisonai-unauthenticated-api
description: The npm `praisonai` package's TypeScript `AgentOS` HTTP server defaults to `0.0.0.0` and exposes unauthenticated API endpoints (`/api/agents`, `/api/chat`), allowing attackers to disclose agent configurations and invoke agents without authorization, leading to potential data exfiltration, unauthorized actions, and resource consumption.
date: "2026-06-18T14:48:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - api-abuse
  - unauthenticated-access
  - information-disclosure
  - server-side-request-forgery
  - web
  - node.js
  - npm
vendors:
  - PraisonAI
products:
  - praisonai (npm package) (>= 1.6.0, <= 1.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Resource Hijacking
references:
  - https://github.com/advisories/GHSA-9752-mhqh-h34f
rules:
  - title: Detect Unauthenticated PraisonAI AgentOS Agent Listing
    description: Detects unauthenticated HTTP GET requests to the /api/agents endpoint of the PraisonAI AgentOS server, indicating information disclosure attempts.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1592.002
    data_sources:
      - webserver
  - title: Detect Unauthenticated PraisonAI AgentOS Agent Invocation
    description: Detects unauthenticated HTTP POST requests to the /api/chat endpoint of the PraisonAI AgentOS server, indicating unauthorized agent invocation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - impact
      - initial_access
    techniques:
      - T1059.007
      - T1190
      - T1498
    data_sources:
      - webserver
rules_count: 2
---

The npm `praisonai` package, specifically versions `>= 1.6.0` through `1.7.1`, contains a critical vulnerability in its TypeScript `AgentOS` HTTP server component. This server defaults to binding on `0.0.0.0` (all network interfaces) and fails to implement any authentication or authorization checks for sensitive API endpoints. Attackers who can reach a running `AgentOS` instance can unauthenticatedly enumerate agent names, roles, and partial instructions via `GET /api/agents`, and crucially, can invoke configured agents via `POST /api/chat`. This directly contradicts PraisonAI's own security documentation regarding hardened API servers and exposes organizations using the affected versions to significant risks, including unauthorized data access, manipulation of systems through agent actions, and resource exhaustion.

## Attack Chain

1.  Attacker identifies an internet-facing host running the `praisonai` `AgentOS` server (e.g., on default port 8000), which is listening on `0.0.0.0`.
2.  Attacker sends an unauthenticated `GET` request to `/api/agents` (or a configured `apiPrefix`) to enumerate active agent names, roles, and up to 100 characters of their instructions.
3.  The `AgentOS` server responds with sensitive metadata, such as an agent named "finance-admin" with instructions like "poc SECRET: refund-wire-tool may alter customer balances".
4.  Attacker crafts a malicious prompt or command based on the disclosed agent information and observed functionality.
5.  Attacker sends an unauthenticated `POST` request to `/api/chat` (or `apiPrefix/chat`), containing the malicious input targeted at a selected agent.
6.  The `AgentOS` server invokes the target agent's `chat` function with the attacker's input, triggering unauthorized actions within the agent's configured environment.
7.  Depending on the agent's capabilities (e.g., access to tools, external APIs, credentials, file system), this leads to data exfiltration, system modification, or resource consumption.

## Impact

An attacker successfully exploiting this vulnerability can cause severe damage. The primary impact is unauthorized access and control over configured PraisonAI agents. This can lead to the compromise of sensitive data through `GET /api/agents` revealing internal workflows and specific instructions, or more critically, through `POST /api/chat` by inducing agents to exfiltrate data, interact with internal systems, or manipulate workflows. While the report does not claim arbitrary code execution by default, if agents are configured with access to tools (e.g., file system, shell execution, external APIs with credentials), unauthenticated invocation effectively becomes an entry point for those powerful capabilities, leading to potential complete system compromise or data destruction. All organizations deploying `praisonai` npm package versions `>= 1.6.0, <= 1.7.1` in an exposed manner are at risk.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM for webserver logs to detect unauthenticated access attempts to `/api/agents` and `/api/chat`.
*   Ensure your network perimeter blocks unsolicited inbound connections to `praisonai AgentOS` instances running on `0.0.0.0` and default ports (e.g., 8000) from untrusted networks.
*   Prioritize updating the `praisonai` npm package to a fixed version once released; if an immediate patch is unavailable, implement custom authentication middleware for affected `AgentOS` instances.
*   Monitor web server logs for `GET` requests to `/api/agents` and `POST` requests to `/api/chat` originating from unexpected source IPs or without expected authentication headers, as detected by the rules.
