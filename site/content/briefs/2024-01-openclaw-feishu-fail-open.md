---
title: 'OpenClaw Feishu Webhook Vulnerability: Unauthenticated Command Execution'
slug: 2024-01-openclaw-feishu-fail-open
description: OpenClaw versions before 2026.4.15 are vulnerable to unauthenticated webhook or card-action traffic due to missing encryption key configuration and improper handling of card-action callbacks, potentially allowing network-triggered access to OpenClaw command handling without Feishu signature or replay protection.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - openclaw
  - feishu
  - webhook
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-xh72-v6v9-mwhc
rules:
  - title: Detect OpenClaw Feishu Webhook Requests Without Encryption Key
    description: Detects OpenClaw Feishu webhook requests where the encryptKey is missing, indicating a potential attempt to exploit the vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Card-Action Callbacks with Blank Tokens
    description: Detects OpenClaw card-action callbacks with blank tokens, which could indicate an attempt to bypass authentication.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, when configured with Feishu webhook integration, is susceptible to a critical vulnerability in versions prior to 2026.4.15. This vulnerability stems from the application's failure to properly validate incoming webhook requests and card-action callbacks. Specifically, the application incorrectly accepts configurations without an `encryptKey` and processes card-action callbacks with blank tokens. This fail-open behavior allows unauthenticated traffic to bypass intended security measures, potentially leading to unauthorized command execution within the OpenClaw environment. The vulnerability impacts deployments utilizing Feishu webhook mode, exposing a network-triggered entry point into OpenClaw command handling without the expected Feishu signature or replay protection. This vulnerability was reported by @dhyabi2. Version 2026.4.15 resolves this issue.

## Attack Chain

1. An attacker identifies an OpenClaw deployment using Feishu webhooks without a configured `encryptKey`.
2. The attacker crafts a malicious Feishu webhook request, bypassing signature validation due to the missing `encryptKey`.
3. The attacker sends the crafted webhook request to the OpenClaw endpoint.
4. OpenClaw processes the unauthenticated request, due to the missing `encryptKey` check, forwarding it to command dispatch.
5. Alternatively, the attacker crafts a malicious card-action callback with a blank callback token.
6. OpenClaw fails to reject the card-action callback with the blank token.
7. The unvalidated card-action is processed, triggering unintended commands within OpenClaw.
8. Successful exploitation allows the attacker to execute arbitrary commands within the context of the OpenClaw application.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access and command execution within the OpenClaw application. A vulnerable OpenClaw instance could be leveraged to perform actions such as data exfiltration, system compromise, or denial-of-service attacks. The lack of authentication and validation mechanisms exposes the OpenClaw deployment to significant risk, potentially affecting all users and systems managed by the platform.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.15 or later to remediate the vulnerability. This version enforces validation of Feishu webhooks and card-action callbacks, preventing unauthenticated access (reference: Affected versions).
*   Ensure that the `encryptKey` is properly configured for Feishu webhook integrations. The application will now refuse to start without it (reference: `extensions/feishu/src/monitor.transport.ts`).
*   Deploy the Sigma rule provided below to detect attempts to exploit this vulnerability by monitoring for webhook requests without proper authentication or card-action callbacks with missing tokens.
