---
title: OpenClaw Node Pairing Reconnect Command Escalation
slug: 2026-04-openclaw-privesc
description: A vulnerability in OpenClaw allows a previously paired node to reconnect with a broader command set, including exec-capable commands, without requiring the operator/admin re-pairing path, leading to potential privilege escalation.
date: "2026-04-09T17:35:53Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-5wj5-87vq-39xm
rules:
  - title: Detect OpenClaw Reconnect Privilege Escalation
    description: Detects when a previously paired node reconnects with escalated privileges, specifically when exec-capable commands are used after reconnection.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: Detect Attempted OpenClaw Command Execution with Elevated Privileges
    description: Detects when a node attempts to execute commands requiring elevated privileges after reconnecting to OpenClaw. This could be an indicator of the privilege escalation vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw, a user-controlled local assistant, is vulnerable to a privilege escalation issue. Specifically, a previously paired node can reconnect to the OpenClaw system and execute a broader set of commands than initially authorized. This includes commands capable of arbitrary code execution, potentially bypassing the intended operator/admin re-pairing security mechanism. This vulnerability affects OpenClaw versions 2026.4.5 and earlier. The vulnerability was reported by @zsxsoft and @KeenSecurityLab and patched in version 2026.4.8. This bypass occurs because the system doesn't properly validate the scope of commands allowed upon reconnection, allowing an attacker to leverage an old pairing to gain elevated privileges.

## Attack Chain

1. A node is initially paired with OpenClaw with a limited set of command permissions.
2. The node disconnects from the OpenClaw system.
3. The OpenClaw system does not properly invalidate or restrict the node's permissions upon disconnection.
4. The node reconnects to OpenClaw.
5. OpenClaw incorrectly authorizes the node with the broader, exec-capable command set.
6. The node executes commands with escalated privileges.
7. The attacker gains unauthorized access to sensitive data or system resources.
8. The attacker maintains persistent access or performs further malicious actions.

## Impact

Successful exploitation of this vulnerability allows a malicious or compromised node to gain elevated privileges within the OpenClaw system. This could lead to unauthorized access to sensitive data, arbitrary code execution, and full system compromise. This affects any OpenClaw installation running versions 2026.4.5 or earlier. The impact is significant as it bypasses the intended security model of requiring re-pairing by an operator/admin for elevated privileges.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.4.8 or later to remediate the vulnerability.
*   Deploy the Sigma rule `DetectOpenClawReconnectPrivilegeEscalation` to monitor for exploitation attempts via command execution.
