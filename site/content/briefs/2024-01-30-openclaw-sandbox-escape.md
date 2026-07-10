---
title: OpenClaw Sandboxed Agent Exec Routing Escape
slug: 2024-01-30-openclaw-sandbox-escape
description: 'A vulnerability in the openclaw npm package (versions >= 2026.4.5 and < 2026.4.10) allows a sandboxed agent to bypass intended sandbox execution paths by requesting `host: "node"`, potentially leading to code execution on a remote node.'
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - npm
  - sandbox-escape
  - openclaw
vendors:
  - OpenClaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-736r-jwj6-4w23
rules:
  - title: Detect OpenClaw Sandbox Escape Attempt via Host Override
    description: 'Detects attempts to bypass the sandbox by requesting `host: "node"` in OpenClaw environments'
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Remote Node Execution
    description: Detects suspicious processes initiated on a remote node potentially exploited through OpenClaw sandbox escape.
    platform: sigma
    severity: medium
    tactics:
      - execution
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The OpenClaw library, an npm package, contains a vulnerability that allows sandboxed agents to escape their intended execution environment. Specifically, by manipulating the `host` parameter in an execution request to `"node"`, a malicious agent can bypass the sandbox routing boundary. This causes the execution to be routed to a remote node instead of remaining within the controlled sandbox. This issue affects versions of the `openclaw` package between 2026.4.5 and 2026.4.10. This vulnerability was reported by @zsxsoft, with sponsorship from @KeenSecurityLab and @qclawer, and patched in version 2026.4.10. The latest release, version 2026.4.14, includes the fix. Defenders should upgrade to version 2026.4.10 or later to mitigate this risk.

## Attack Chain

1.  A sandboxed agent is compromised or created with malicious intent.
2.  The agent crafts an execution request using the vulnerable `openclaw` library.
3.  The agent modifies the execution request to include the parameter `host: "node"`.
4.  The `openclaw` library incorrectly routes the execution request due to the `host` parameter override.
5.  Instead of executing within the sandboxed environment, the request is routed to a remote node.
6.  The remote node receives the execution request and processes it.
7.  Malicious code is executed on the remote node, bypassing the intended sandbox restrictions.

## Impact

Successful exploitation of this vulnerability allows a sandboxed agent to execute arbitrary code on a remote node. This can lead to a compromise of the remote node, potentially allowing the attacker to gain unauthorized access to sensitive data, escalate privileges, or perform other malicious actions. This can also affect any service or applications running on the remote node. This issue has the potential to impact any system using a vulnerable version of the `openclaw` library.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.4.10 or later to remediate the vulnerability.
*   Monitor npm package installations for vulnerable versions of `openclaw` (>= 2026.4.5 < 2026.4.10).
*   Implement additional security measures to restrict the capabilities of sandboxed agents.
*   Deploy the Sigma rules below to detect suspicious process creations related to the execution of commands from unexpected hosts within the openclaw environment.
