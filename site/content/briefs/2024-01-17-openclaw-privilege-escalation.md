---
title: OpenClaw Unauthorized Channel Allowlist Modification via chat.send
slug: 2024-01-17-openclaw-privilege-escalation
description: A vulnerability in OpenClaw versions 2026.3.23 and earlier allows a gateway client with `operator.write` scope to bypass intended privilege separation and persist channel authorization policy.
date: "2024-01-17T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - privilege-escalation
  - allowlist
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-94pw-c6m8-p9p9
rules:
  - title: OpenClaw Allowlist Modification via chat.send
    description: Detects the use of /allowlist commands within chat.send from operator.write clients, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: OpenClaw Unauthorized Config File Write
    description: Detects writes to the OpenClaw config file performed without operator.admin privileges, possibly indicating an exploitation attempt of the allowlist vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions 2026.3.23 and earlier contain a privilege escalation vulnerability that allows an attacker with `operator.write` scope to modify channel authorization policies that should be restricted to `operator.admin` scope. This occurs due to a missing sink-side check on the `/allowlist` command when called internally through the `chat.send` function. A malicious actor can leverage this vulnerability to widen DM or group allowlists for channels, bypassing intended authorization controls. The vulnerability was patched in OpenClaw version 2026.3.24, which is the current shipping release. This bypass weakens the documented control-plane privilege split between write actions and admin-only persistent authorization mutation.

## Attack Chain

1. An attacker authenticates to the OpenClaw gateway with `operator.write` scope.
2. The attacker sends a message via the `chat.send` API.
3. `chat.send` builds an internal message context with `CommandAuthorized: true` and includes `GatewayClientScopes`.
4. `resolveCommandAuthorization(...)` translates this into `isAuthorizedSender=true` because no stricter override is present.
5. The attacker uses the `/allowlist add|remove` command within the `chat.send` message content.
6. The `/allowlist` handler clones the parsed config and calls `plugin.allowlist.applyConfigEdit(...)`.
7. The handler validates the result and attempts to persist it with `writeConfigFile(validated.config)`.
8. Due to the missing `operator.admin` check before the write occurs, the configuration is updated, widening the DM or group allowlists for the targeted channel.

## Impact

A gateway client limited to `operator.write` can persist first-party channel authorization policy, which should require `operator.admin`. This allows the attacker to widen DM or group allowlists for channels using the `/allowlist` functionality. Successfully exploiting this vulnerability weakens the security posture of the OpenClaw gateway by undermining the intended access control mechanisms. Attackers can potentially read private communications.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.24 or later to patch the vulnerability (reference: GitHub advisory).
*   Monitor gateway logs for the use of `/allowlist add` or `/allowlist remove` commands originating from `operator.write`-scoped clients (reference: Attack Chain).
*   Implement rate limiting on the `chat.send` API to mitigate potential abuse (reference: Attack Chain).
