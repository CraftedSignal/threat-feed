---
title: pytonapi Webhook Custom Path Authentication Bypass (GHSA-3fcr-jvgp-7f58)
slug: 2026-07-pytonapi-webhook-auth-bypass
description: The pytonapi library, specifically version 2.2.0, contains an authentication bypass vulnerability (GHSA-3fcr-jvgp-7f58) in its TonapiWebhookDispatcher, allowing unauthenticated remote attackers to send forged payloads to custom webhook endpoints, triggering victim-defined business logic and causing integrity impact.
date: "2026-07-28T17:10:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - webhooks
  - python
vendors:
  - pytonapi Project
products:
  - pytonapi (< 2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can POST arbitrary forged payloads to the custom webhook endpoint and trigger victim-defined handlers with full integrity impact.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3fcr-jvgp-7f58
rules:
  - title: Detect Successful POST to pytonapi Custom Webhook Path (GHSA-3fcr-jvgp-7f58)
    description: Detects HTTP POST requests to pytonapi TonapiWebhookDispatcher custom paths that successfully return 200 OK. This could indicate exploitation of GHSA-3fcr-jvgp-7f58, an authentication bypass vulnerability, if the pytonapi application is vulnerable.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The `pytonapi` library, specifically version 2.2.0, is affected by an authentication bypass vulnerability, identified as GHSA-3fcr-jvgp-7f58. The `TonapiWebhookDispatcher` component fails to properly validate the `Authorization` header when a webhook handler is configured using the documented `path=` argument, creating a custom endpoint. During setup, bearer tokens are only associated with default suffix paths, leaving custom paths without a corresponding token entry. Consequently, when an incoming request targets a custom path, the system's authentication check is silently bypassed as `expected_token` evaluates to `None`. This "fail-open" mechanism allows an unauthenticated remote attacker to send forged JSON payloads to these custom webhook endpoints. This can trigger victim-defined business logic, such as payment processing or account state updates, with attacker-controlled data, leading to severe integrity impact and potential financial or operational harm. Any application integrating this specific version of `pytonapi` and utilizing custom webhook paths is vulnerable.

## Attack Chain

1. **Attacker Reconnaissance**: An attacker identifies a target application utilizing `pytonapi` with `TonapiWebhookDispatcher` configured to use a custom webhook path (e.g., `/hook/custom`).
2. **Payload Crafting**: The attacker constructs a malicious JSON payload designed to mimic a legitimate `pytonapi` webhook event (e.g., an `account_tx` notification) but containing forged data (e.g., a `FORGED_TX_HASH`).
3. **Exploitation Attempt**: The attacker sends an unauthenticated HTTP POST request to the application's custom webhook endpoint (e.g., `https://victim.example/hook/custom`), embedding the forged JSON payload in the request body. The `Authorization` header is either omitted or contains an incorrect bearer token.
4. **Vulnerability Trigger**: The `pytonapi` `TonapiWebhookDispatcher` instance receives the incoming HTTP request. When processing the request for the custom path, the dispatcher attempts to retrieve an `expected_token` from its internal map using `self._tokens.get(path)`.
5. **Authentication Bypass**: Because custom paths are never registered in `_tokens`, the `expected_token` variable becomes `None`. This causes the subsequent authentication check `if expected_token is not None` to evaluate to `False`, silently bypassing the entire authentication mechanism.
6. **Payload Processing**: The dispatcher proceeds to parse the attacker's forged JSON payload as if it were a legitimate and authenticated webhook event.
7. **Impact Delivery**: The victim-defined asynchronous event handler (e.g., `on_custom_tx`) associated with the custom path is invoked by the dispatcher, receiving and processing the attacker-controlled forged data.
8. **Adverse Action**: The victim's application executes its business logic (e.g., updating account balances, initiating payments, dispatching notifications) based on the attacker's forged information, leading to financial loss, data corruption, or other integrity compromises.

## Impact

This vulnerability, classified as Improper Authentication (CWE-287), critically impacts the integrity of applications using `pytonapi` version 2.2.0 that have registered webhook handlers with the `path=` argument. There is no specific number of victims or sectors identified, but any application meeting these criteria is fully exposed. A successful exploitation allows an unauthenticated remote attacker to inject arbitrary, forged TON blockchain event data, directly triggering and manipulating victim-defined business logic. This can lead to severe consequences such as fraudulent payment processing, incorrect account state updates, or the dispatch of misleading notifications, resulting in financial losses or operational disruption. Confidentiality is not directly affected, but data integrity and the reliability of automated processes are significantly compromised.

## Recommendation

* Update `pytonapi` to a patched version greater than 2.2.0 to resolve the GHSA-3fcr-jvgp-7f58 authentication bypass.
* Deploy the Sigma rule "Detect Successful POST to pytonapi Custom Webhook Path (GHSA-3fcr-jvgp-7f58)" to your SIEM solution to identify potential exploitation attempts against vulnerable `pytonapi` applications.
* Review webserver access logs for `webserver` entries indicating successful (HTTP 200 OK) POST requests to custom webhook paths (e.g., `/hook/custom`) that lack expected authentication headers or originate from unexpected sources.
