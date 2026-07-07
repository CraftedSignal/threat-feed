---
title: OpenClaw Hook Ingress Privilege Escalation via CVE-2026-53814
slug: 2026-07-openclaw-privesc
description: A high-severity vulnerability, CVE-2026-53814, in OpenClaw allows an attacker with a valid hook token to escalate privileges by causing hook-triggered agent runs to incorrectly receive owner-scoped MCP tool authority, enabling unauthorized access to owner-only functions like manipulating persistent cron state.
date: "2026-07-03T12:15:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - privilege-escalation
  - web-application
vendors:
  - OpenClaw
products:
  - openclaw (< 2026.5.20)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A hook-triggered run could select a bundled CLI backend that received owner-scoped MCP loopback authority instead of a scope appropriate for hook ingress. A caller with the hook token could cause the spawned CLI runtime to see or call MCP tools that should have been owner-only.
    confidence_band: high
cves:
  - id: CVE-2026-53814
    cvss: 8.3
    epss: 0.00281
references:
  - https://github.com/advisories/GHSA-6fvr-66p3-3qj4
---

A high-severity privilege escalation vulnerability, tracked as CVE-2026-53814, has been identified in OpenClaw's hook ingress mechanism. Affecting versions prior to `2026.5.20`, this flaw allows a malicious actor possessing a valid hook token to execute automated agent runs with elevated privileges. Specifically, the system incorrectly grants owner-scoped MCP (Managed Control Plane) tool authority to these hook-triggered runs, instead of limiting them to the intended scope appropriate for hook ingress. This misconfiguration enables an attacker to access and invoke MCP tools that should be restricted to owner-only access, potentially leading to unauthorized actions within the system. The issue was disclosed on July 2, 2026, and primarily impacts deployments where OpenClaw hooks are enabled, the `/hooks/agent` endpoint is accessible with a valid hook token, and a bundled CLI backend can be selected for the run.

## Attack Chain

1.  **Attacker obtains a valid OpenClaw hook token**: This initial access vector is not detailed in the advisory, but is a prerequisite for exploitation.
2.  **Attacker crafts a request to the `/hooks/agent` endpoint**: The request is made to the exposed hook endpoint, including the valid hook token.
3.  **Attacker selects a bundled CLI backend for the hook-triggered run**: The attacker's request is designed to cause the OpenClaw system to utilize a specific bundled CLI backend.
4.  **Vulnerable system incorrectly assigns owner-scoped MCP authority**: Due to CVE-2026-53814, the spawned CLI runtime for the hook-triggered run is granted owner-level MCP loopback authority, despite being initiated via a hook token that should have limited scope.
5.  **Attacker leverages elevated privileges to access owner-only MCP tools**: With the unauthorized owner authority, the attacker can now interact with internal MCP tools that are normally restricted.
6.  **Attacker performs unauthorized actions**: The specific impact depends on the available MCP tools, but an example proof-of-concept involved manipulating persistent cron state, indicating potential for system-level persistence or data alteration.

## Impact

Successful exploitation of CVE-2026-53814 grants an attacker holding a valid hook token the ability to bypass intended privilege boundaries within the OpenClaw application. This allows them to execute CLI commands with owner-level authority, accessing and utilizing MCP tools that are designed to be restricted. The concrete impact is highly dependent on which specific MCP tools are deployed and accessible; however, as demonstrated by the reported proof of concept, this can include critical actions such as modifying persistent cron states. While no specific victim counts or targeted sectors were disclosed, any organization utilizing vulnerable OpenClaw configurations with enabled hooks is at risk of unauthorized administrative control and potential system compromise.

## Recommendation

*   Upgrade all affected `npm/openclaw` instances to version `2026.5.20` or later to remediate CVE-2026-53814 immediately.
*   Restrict network access to the `/hooks/agent` endpoint to only trusted sources, as indicated in the advisory context for CVE-2026-53814.
*   Disable OpenClaw hooks if they are not actively required for automation workflows, reducing the attack surface related to CVE-2026-53814.
*   Ensure all OpenClaw hook tokens are kept secret and treated as highly sensitive credentials.
