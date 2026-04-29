---
title: OpenClaw Paired Node Escalation to Gateway RCE via Unrestricted Agent Dispatch
slug: 2026-04-openclaw-rce
description: A vulnerability in OpenClaw versions 2026.3.28 and earlier allows a paired node to escalate privileges to achieve remote code execution on the gateway via unrestricted node.event agent dispatch, requiring an existing foothold on a trusted paired node.
date: "2026-04-03T03:22:05Z"
type: coverage
types:
  - coverage
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

OpenClaw, a package available on npm, is vulnerable to a privilege escalation issue. The vulnerability resides in the handling of `node.event` agent dispatch, allowing a compromised or malicious paired node to execute commands on the gateway with elevated privileges. This is possible because the gateway trusts the paired node and doesn't sufficiently restrict the `node.event` agent's capabilities. While the attacker requires a pre-existing foothold on a paired node, successful exploitation leads to remote code execution on the gateway. This vulnerability affects OpenClaw versions up to and including 2026.3.28. Version 2026.3.31 addresses this vulnerability, as reported by AntAI Security Lab. Defenders should upgrade immediately.

## Attack Chain

1. An attacker gains initial access to a paired node within the OpenClaw environment.
2. The attacker leverages their access to the paired node to craft a malicious `node.event` agent request.
3. This crafted request is designed to exploit the unrestricted agent dispatch vulnerability.
4. The paired node sends the malicious `node.event` agent request to the OpenClaw gateway.
5. The gateway, trusting the paired node, processes the request without adequate validation.
6. Due to the lack of restrictions, the agent dispatch executes commands on the gateway system.
7. The attacker achieves remote code execution on the OpenClaw gateway.
8. The attacker can then perform further actions, such as data exfiltration or lateral movement.

## Impact

Successful exploitation of this vulnerability allows an attacker with a foothold on a paired node to gain remote code execution on the OpenClaw gateway. This could lead to complete compromise of the gateway, potentially impacting all connected systems and data. The severity is high because the attacker can leverage this vulnerability to pivot from a less privileged node to the critical gateway server.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.3.31 or later to patch the vulnerability.
*   Implement input validation and sanitization on the gateway side to prevent malicious `node.event` agent requests from being processed.
*   Monitor process creation events on the OpenClaw gateway for unusual or unauthorized processes originating from the OpenClaw application. Deploy the provided Sigma rule for process creation to detect suspicious activity on the gateway.
