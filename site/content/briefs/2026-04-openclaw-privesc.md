---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-41378)
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.31 contains a privilege escalation vulnerability allowing paired nodes with role=node to dispatch node.event agent requests with unrestricted gateway-side tool access, leading to remote code execution.
date: "2026-04-28T19:37:40Z"
severities:
  - critical
tags:
  - privilege-escalation
  - remote-code-execution
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-41378
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41378
rules:
  - title: Detect Suspicious OpenClaw Agent Requests
    description: Detects suspicious OpenClaw agent requests that could indicate privilege escalation attempts exploiting CVE-2026-41378.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Gateway Remote Code Execution via Agent Request
    description: Detects potential remote code execution attempts on the OpenClaw gateway by monitoring for specific commands within agent requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
      - T1059.005
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.31 is vulnerable to a privilege escalation flaw. The vulnerability allows paired nodes configured with the role "node" to dispatch `node.event agent` requests, bypassing intended restrictions on gateway-side tool access. An attacker who has already compromised a trusted paired node with valid credentials can exploit this vulnerability to elevate their privileges. By abusing the unrestricted `agent.request` dispatch, they can achieve arbitrary remote code execution on the gateway. This vulnerability poses a significant threat as it grants unauthorized access and control over the OpenClaw gateway.

## Attack Chain

1. An attacker gains initial access to a paired node with the `role=node` configuration.
2. The attacker authenticates to the OpenClaw gateway using the compromised node's credentials.
3. The attacker crafts a malicious `node.event agent` request.
4. The crafted request is dispatched to the OpenClaw gateway.
5. The gateway improperly processes the request, failing to enforce proper access controls.
6. The unrestricted `agent.request` dispatch allows the attacker to execute arbitrary commands.
7. The attacker executes a payload of their choice, such as deploying a reverse shell.
8. The attacker achieves remote code execution on the OpenClaw gateway, gaining complete control.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control of the OpenClaw gateway. This can lead to data breaches, system compromise, and disruption of services. Given the CVSS v3.1 base score of 8.8, this vulnerability is considered critical. The number of affected installations is unknown, but organizations using OpenClaw versions prior to 2026.3.31 are at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41378.
*   Implement the Sigma rule `Detect Suspicious OpenClaw Agent Requests` to identify potentially malicious `node.event agent` requests targeting the OpenClaw gateway.
*   Monitor network traffic for unusual activity originating from OpenClaw nodes that could indicate exploitation attempts.
