---
title: OpenClaw Paired Node Escalation to Gateway RCE via Unrestricted Agent Dispatch
slug: 2026-04-openclaw-rce
description: A vulnerability in OpenClaw versions 2026.3.28 and earlier allows a paired node to escalate privileges to achieve remote code execution on the gateway via unrestricted node.event agent dispatch, requiring an existing foothold on a trusted paired node.
date: "2026-04-03T03:22:05Z"
severities:
  - high
tags:
  - openclaw
  - rce
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gjm7-hw8f-73rq
rules:
  - title: Detect Suspicious Process Creation from OpenClaw Gateway
    description: Detects suspicious process creation events originating from the OpenClaw gateway application, which could indicate exploitation of the RCE vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Node Event Agent Request Command Execution
    description: Detects command execution associated with OpenClaw Node Event Agent Requests.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw, a package available on npm, is vulnerable to a privilege escalation issue. The vulnerability resides in the handling of `node.event` agent dispatch, allowing a compromised or malicious paired node to execute commands on the gateway with elevated privileges. This is possible because the gateway trusts the paired node and doesn't sufficiently restrict the `node.event` agent's capabilities. While the attacker requires a pre-existing foothold on a paired node, successful exploitation…
