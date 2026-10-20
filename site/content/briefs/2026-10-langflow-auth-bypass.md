---
title: IBM Langflow OSS Authorization Bypass Vulnerability
slug: 2026-10-langflow-auth-bypass
description: IBM Langflow OSS versions 1.0.0 through 1.12.4 are vulnerable to an authorization bypass in message endpoints that enables unauthorized session hijacking, message deletion, and prompt injection.
date: "2026-10-20T00:30:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ibm:langflow:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - authorization-bypass
  - cve-2026-107366
vendors:
  - IBM
products:
  - Langflow OSS (1.0.0-1.12.4)
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107366
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to Langflow message API endpoints via Web Application Firewall or reverse proxy.
      owner: SOC
      due: 24h
      evidence: Vulnerability exists in message endpoints that perform no ownership verification.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Langflow OSS to the latest secure version once released.
      owner: IT Operations
      addresses: CVE-2026-107366
      evidence: IBM Langflow OSS 1.0.0 through 1.12.4 contains three message endpoints that perform no ownership verification.
---

IBM Langflow OSS versions 1.0.0 through 1.12.4 contain a critical authorization vulnerability within three message endpoints. The root cause is a failure to implement ownership verification during message processing requests. An authenticated user can exploit these endpoints to perform operations on messages and sessions belonging to other users. This vulnerability allows for unauthorized bulk deletion of message history, the modification of message content to facilitate prompt injection attacks, and the hijacking of active conversation sessions through session ID reassignment. Because this flaw exists in the application API, it impacts the integrity of user data and the confidentiality of ongoing workflows within the Langflow environment. Defenders should focus on monitoring for anomalous API requests targeting message management endpoints.

## Impact

Successful exploitation results in unauthorized modification or deletion of communication records and full takeover of conversation sessions. This impacts any enterprise sector utilizing Langflow for LLM workflow orchestration, potentially leading to the leakage of sensitive internal prompts or the manipulation of AI-driven decision-making processes.

## Recommendation

- Upgrade IBM Langflow OSS to a version beyond 1.12.4 as soon as the vendor provides a patch.
- Audit API access logs for high-frequency or bulk requests to message endpoints that do not correspond to the authenticated user's standard activity patterns.
- Implement strict network-level access controls for the Langflow management API to limit the exposure of the vulnerable endpoints to authorized administrative subnets only.
