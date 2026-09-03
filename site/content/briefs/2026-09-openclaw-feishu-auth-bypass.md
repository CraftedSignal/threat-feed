---
title: Authorization Bypass in OpenClaw Feishu Permission Tools
slug: 2026-09-openclaw-feishu-auth-bypass
description: An authorization flaw in the OpenClaw Feishu npm package allows lower-trust callers to bypass per-account disablement settings and execute unauthorized actions.
date: "2026-09-03T18:04:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - supply-chain
  - npm
vendors:
  - OpenClaw
products:
  - '@openclaw/feishu (< 2026.6.9-beta.1)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w8wf-3qvj-6xqf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade @openclaw/feishu to version 2026.6.9 or later
      owner: IT Operations
      due: 48h
      evidence: The first stable patched version is 2026.6.9.
  mitigation_plan:
    - priority: immediate
      action: Disable Feishu permission tools in the OpenClaw Gateway if not strictly needed
      owner: IT Operations
      addresses: '@openclaw/feishu authorization bypass'
      evidence: disable the affected feature when it is not needed.
---

The OpenClaw Feishu permission tool component, specifically within the npm package @openclaw/feishu, contains an authorization flaw that allows callers to ignore per-account disablement settings. This vulnerability stems from improper validation of authorization policies, where lower-trust callers or specially crafted input paths can execute actions that should have been restricted.

The issue enables an attacker or a lower-trust entity to perform operations within the Gateway environment that exceed their intended authorization boundary. Because OpenClaw operates on a trusted-operator model, this bypass significantly degrades the isolation between different user tiers. Defenders must ensure that access to the affected Feishu tools is strictly limited to authorized operators, and that the feature is disabled in environments where its usage is not strictly required. The vulnerability is resolved in version 2026.6.9.

## Impact

Successful exploitation allows a lower-trust actor to bypass established security policies and perform unauthorized actions within the Feishu integration. The total impact depends on the operator's specific configuration; in environments where mutually untrusted users share a single Gateway, this could lead to unauthorized access to Feishu resources and potential privilege escalation.

## Recommendation

1. Upgrade the `@openclaw/feishu` package to version 2026.6.9 or later to remediate the vulnerability.
2. Disable the affected Feishu permission tool functionality if it is not required for daily operations.
3. Narrow existing channel and tool allowlists to restrict access to trusted operators only.
4. Avoid sharing a single OpenClaw Gateway instance between users or entities that do not share the same trust level.
