---
brief_id: brief-2026-10-29-volto-chatbot-danswer-proxy
event_id: brief-2026-10-29-volto-chatbot-danswer-proxy
revision: 1
activity_at: "2026-10-29T18:37:50Z"
title: '@eeacms/volto-chatbot: Unauthenticated Danswer API Confused Deputy Proxy'
slug: 2026-10-volto-chatbot-danswer-proxy
description: An unauthenticated Express middleware vulnerability in @eeacms/volto-chatbot allows remote attackers to proxy requests to the Danswer API using the server’s own privileged service credentials.
date: "2026-10-29T18:37:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Lab environment validation defined via provided Dockerfile
tags:
  - web-application
  - proxy
  - api-security
vendors:
  - EEA
products:
  - '@eeacms/volto-chatbot (2.0.3)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can invoke arbitrary Danswer API operations — including privileged admin endpoints — as the configured service account.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w9x9-j56r-h98r
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block all incoming traffic to /_v1_da/ at the perimeter or host firewall
      owner: SOC
      due: 2h
      evidence: Path is unconditionally routed to proxyMiddleware without auth
  hunt_leads:
    - lead: Search Danswer backend logs for unexpected requests sourced from the Volto server IP
      technique_id: T1190
      data_needed:
        - Danswer backend webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Middleware proxies requests to Danswer API using server credentials
  mitigation_plan:
    - priority: immediate
      action: Restrict network exposure and wait for patched version
      owner: IT Operations
      addresses: '@eeacms/volto-chatbot'
      evidence: Default-on vulnerability in production configurations
---

The `@eeacms/volto-chatbot` package contains a configuration issue in its Express middleware that exposes an unauthenticated proxy to the Danswer API. The vulnerability (CWE-862) resides in the `/_v1_da/` route, which forwards requests to the configured `DANSWER_URL` without performing authorization checks or path validation. When the add-on is configured with `DANSWER_API_KEY` or session cookies, the middleware silently attaches these credentials to requests. An unauthenticated attacker can control the destination path and HTTP method, effectively acting as the service account to perform unauthorized actions against the Danswer backend.

## Attack Chain

1. The attacker identifies an instance of `@eeacms/volto-chatbot` accessible over the network.
2. The attacker sends a crafted, unauthenticated HTTP request to the `/_v1_da/` endpoint on the Volto server.
3. The `proxyMiddleware` intercepts the request without requiring authentication or session validation.
4. The middleware extracts the attacker-supplied path from the request URL.
5. The middleware constructs an upstream URL by appending the attacker's path to the configured `DANSWER_URL`.
6. The middleware silently attaches the server-side `DANSWER_API_KEY` or session cookie to the outbound request headers.
7. The middleware forwards the request to the Danswer API, which processes the action as a privileged command from the service account.

## Impact

Successful exploitation allows unauthenticated attackers to perform actions as the Danswer service account. Depending on the service account's permissions, this may lead to the unauthorized disclosure of sensitive documents and conversation history, or the mutation of system state, such as deleting users or creating chat sessions.

## Recommendation

- Upgrade `@eeacms/volto-chatbot` to a patched version once released by the maintainers.
- If a patch is unavailable, immediately restrict network access to the Volto server to trusted internal segments.
- Implement a Web Application Firewall (WAF) rule to block all requests to the `/_v1_da/` path.
- Audit Danswer API access logs for requests originating from the Volto server IP address with suspicious or administrative paths (e.g., `/admin/`).
