---
title: OpenClaw Scoped Chat Route Inheritance Could Bypass Admin Command Scope Gates
slug: 2026-07-openclaw-scope-bypass
description: A vulnerability in OpenClaw allows an attacker with `operator.write` privileges to bypass intended administrative command scope gates by delivering a scoped Gateway `chat.send` request through an inherited external route, leading to unauthorized execution of critical administrative commands.
date: "2026-07-03T12:14:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - openclaw
  - application-security
vendors:
  - OpenClaw
products:
  - openclaw (< 2026.5.18)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a scoped Gateway `chat.send` request delivered through an inherited external route could be evaluated as an external-channel command while still carrying the lower Gateway client scopes. Commands that should have required `operator.approvals` or `operator.admin` could run with only `operator.write` in this routed context.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hw9r-h9mr-4jff
---

A high-severity vulnerability has been identified in OpenClaw that enables privilege escalation for certain scoped Gateway clients. Specifically, a `chat.send` request, when delivered through an inherited external route, can be incorrectly evaluated as an external-channel command while retaining the lower Gateway client scopes. This flaw affects OpenClaw deployments where a scoped Gateway caller with `operator.write` permissions can send commands into sessions utilizing external delivery routes. This bypasses security checks that typically require higher `operator.approvals` or `operator.admin` scopes for critical administrative functions. The vulnerability impacts versions prior to `2026.5.18` and allows for unauthorized execution of plugin, config, MCP, allowlist, and ACP mutations.

## Attack Chain

1.  An attacker obtains or leverages existing `operator.write` privileges within a scoped Gateway client in an OpenClaw deployment.
2.  The attacker crafts a malicious `chat.send` request targeting administrative functions (e.g., plugin, config, MCP, allowlist, or ACP mutations).
3.  The crafted `chat.send` request is intentionally delivered into a session that possesses an inherited external delivery route.
4.  The OpenClaw system evaluates this specific request path as an external-channel command, despite originating from a scoped Gateway client.
5.  During this evaluation, the request erroneously retains the lower `operator.write` client scopes, rather than requiring the higher `operator.approvals` or `operator.admin` scopes mandated for the targeted administrative commands.
6.  The administrative command is executed with insufficient privileges, bypassing the intended security scope gates and achieving privilege escalation within the OpenClaw environment.

## Impact

The successful exploitation of this vulnerability allows an attacker with only `operator.write` permissions to execute commands that should explicitly require higher `operator.approvals` or `operator.admin` scopes. This includes critical administrative commands related to plugin management, configuration changes, Message Control Protocol (MCP) modifications, allowlist adjustments, and Access Control Policy (ACP) mutations. Such unauthorized execution can lead to severe system compromise, data manipulation, unauthorized access, and potentially full control over the OpenClaw instance, undermining the integrity and security posture of the platform.

## Recommendation

*   Upgrade all OpenClaw instances to version `openclaw@2026.5.18` or later immediately to patch the vulnerability.
*   Review and restrict `operator.write` token grants: Avoid granting `operator.write` tokens to clients that can deliver commands into sessions with external routes unless those clients are explicitly trusted with admin-like command effects.
