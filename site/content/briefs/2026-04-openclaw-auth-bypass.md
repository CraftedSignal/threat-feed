---
title: OpenClaw Matrix Room Control Command Authorization Bypass
slug: 2026-04-openclaw-auth-bypass
description: A vulnerability in OpenClaw versions greater than 2026.3.28 and before 2026.4.15 allowed a Matrix sender paired via DM to bypass room authorization boundaries and execute room control commands without proper authorization.
date: "2026-04-18T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - openclaw
  - matrix
  - authorization-bypass
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2gvc-4f3c-2855
rules:
  - title: Detect OpenClaw Room Control Command Execution from Unauthorized DM User
    description: Detects attempts to execute OpenClaw room control commands by users who are only authorized via DM pairing and not explicitly allowed in the room.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: Detect OpenClaw Control Command with Unexpected Arguments
    description: Detects OpenClaw control command executions with unusual or unexpected arguments which may indicate malicious intent.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw versions prior to 2026.4.15 contained a flaw in Matrix room control-command authorization. The system incorrectly included sender IDs learned from the Matrix DM pairing store in the effective allowlist for room traffic. This meant that a sender who was authorized only for a Matrix DM could potentially authorize room control commands when they also posted in a bot-controlled room. This vulnerability allows a DM-paired Matrix sender to cross the authorization boundary and run Matrix room control commands without being present in the configured room allowlist, room membership list, or group allowlist. The vulnerability affects OpenClaw versions > 2026.3.28 and < 2026.4.15. The issue was reported by @nexrin and Keen Security Lab and patched in version 2026.4.15.

## Attack Chain

1. An attacker establishes a direct message (DM) pairing with the OpenClaw bot.
2. The attacker gains authorization to send messages within the DM channel.
3. The attacker identifies a Matrix room controlled by the OpenClaw bot.
4. The attacker sends a message to the bot-controlled room.
5. Due to the flawed authorization logic, the attacker's sender ID is incorrectly included in the effective allowlist for the room based on the DM pairing.
6. The attacker sends a specially crafted message to the bot-controlled room, containing a control command.
7. The OpenClaw bot, due to the bypassed authorization check, executes the control command.
8. The attacker achieves unauthorized control over the Matrix room, potentially driving privileged OpenClaw behavior.

## Impact

This vulnerability allowed unauthorized users to execute Matrix room control commands within OpenClaw deployments. The impact severity is high because room control commands can drive privileged OpenClaw behavior depending on the deployment's command and tool policy. Successful exploitation could lead to unauthorized modification of room settings, access to sensitive information, or disruption of services managed by the OpenClaw bot. The number of potentially affected deployments is unknown, but all instances running vulnerable versions are at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.15 or later to patch the authorization bypass vulnerability.
*   Review OpenClaw's command and tool policy to understand the scope of potential privileged behavior that could be triggered by room control commands.
*   Deploy the Sigma rule `Detect OpenClaw Room Control Command Execution from Unauthorized DM User` to identify potential exploitation attempts.
*   Monitor OpenClaw logs for unexpected room control command executions, particularly those originating from users with only DM pairing-store entries.
