---
title: OpenClaw Matrix Room Control Command Authorization Bypass
slug: 2026-04-openclaw-auth-bypass
description: A vulnerability in OpenClaw versions greater than 2026.3.28 and before 2026.4.15 allowed a Matrix sender paired via DM to bypass room authorization boundaries and execute room control commands without proper authorization.
date: "2026-04-18T12:00:00Z"
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

OpenClaw versions prior to 2026.4.15 contained a flaw in Matrix room control-command authorization. The system incorrectly included sender IDs learned from the Matrix DM pairing store in the effective allowlist for room traffic. This meant that a sender who was authorized only for a Matrix DM could potentially authorize room control commands when they also posted in a bot-controlled room. This vulnerability allows a DM-paired Matrix sender to cross the authorization boundary and run Matrix room…
