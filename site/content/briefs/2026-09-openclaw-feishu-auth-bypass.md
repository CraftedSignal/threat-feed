---
title: Authorization Bypass in OpenClaw Feishu Package
slug: 2026-09-openclaw-feishu-auth-bypass
description: The OpenClaw feishu package is susceptible to an authorization bypass vulnerability where per-account disablement settings are ignored, potentially allowing lower-trust entities to execute unauthorized actions.
date: "2026-09-03T18:04:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - software-vulnerability
  - supply-chain
vendors:
  - OpenClaw
products:
  - feishu (< 2026.6.9-beta.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In affected versions, a lower-trust caller or configured input path could perform actions that should have required a stronger authorization or policy check.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2q7j-2vhx-56g8
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @openclaw/feishu to 2026.6.9
      owner: IT Operations
      due: 48h
      evidence: The first stable patched version is 2026.6.9.
  mitigation_plan:
    - priority: immediate
      action: Disable Feishu feature in OpenClaw config
      owner: IT Operations
      addresses: Authorization bypass in @openclaw/feishu
      evidence: Before upgrading, restrict the affected feature to trusted operators or disable it when it is not needed.
---

The OpenClaw feishu package (version < 2026.6.9-beta.1) contains an authorization bypass vulnerability that causes the software to ignore per-account disablement configurations. This defect permits a lower-trust caller or a reachable input path to execute operations that should have been restricted by the intended authorization or security policy. Because the Feishu module interacts with external messaging and collaboration services, this flaw poses a significant risk to organizations where Gateway operators may be exposed to untrusted inputs or where service accounts share gateways across different trust boundaries. This vulnerability does not impact the core trusted-operator model of OpenClaw itself, but rather specifically affects the enforcement of access controls within the Feishu integration.

## Impact

The failure to enforce per-account disablement policies may allow unauthorized actions within the Feishu environment, potentially leading to unauthorized data access, message manipulation, or unintended API interactions. The extent of the damage is dependent on the specific configuration of the OpenClaw Gateway and the ability of attackers to route malicious or unauthorized input through the affected Feishu tools.

## Recommendation

- Upgrade the OpenClaw @openclaw/feishu package to version 2026.6.9 or later immediately.
- Disable the affected Feishu feature within the OpenClaw configuration if it is not explicitly required for business operations.
- Review and restrict channel and tool allowlists for the Gateway to limit the impact of potential unauthorized command execution.
- Ensure that separate OpenClaw Gateways are used for mutually untrusted user groups to maintain appropriate isolation boundaries.
