---
title: Authorization Bypass in OpenClaw Windows Node via Command Injection
slug: 2026-09-openclaw-auth-bypass
description: An incorrect authorization vulnerability in OpenClaw Windows Node version < 2026.7.1 allows unauthenticated agents to achieve arbitrary command execution by bypassing command approval policies.
date: "2026-09-30T20:36:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openclaw:windows_node:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - execution
vendors:
  - OpenClaw
products:
  - Windows Node (< 2026.7.1)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Connected gateways or agents can bypass approval rules by placing denied commands behind allowed prefixes using pipe operators or command substitution syntax, achieving arbitrary command execution on Windows hosts.
    confidence_band: high
cves:
  - id: CVE-2026-101880
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101880
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenClaw Windows Node to version 2026.7.1 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-101880 remediation guidance
  hunt_leads:
    - lead: Audit logs for system.run containing pipe operators (|) or command substitution (e.g., $())
      technique_id: T1059.003
      data_needed:
        - Application logs containing command parameters
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Parser fails to split commands on pipe operators or extract command substitutions
  mitigation_plan:
    - priority: immediate
      action: Upgrade OpenClaw Windows Node to 2026.7.1
      owner: IT Operations
      addresses: CVE-2026-101880
      evidence: CVE-2026-101880 advisory
---

OpenClaw Windows Node version 2026.7.1 and earlier contains an incorrect authorization vulnerability in the system.run exec-approval policy. The vulnerability resides within the ExecShellWrapperParser component, which fails to correctly tokenize or sanitize input commands. Specifically, the parser does not properly handle pipe operators or command substitution syntax, allowing a malicious or compromised gateway/agent to append denied commands to otherwise authorized prefixes. By exploiting this parsing logic, an attacker can bypass defined approval rules, leading to unauthorized arbitrary command execution on the host operating system. This issue poses a high risk to organizations relying on OpenClaw for automated system management and task execution.

## Impact

Successful exploitation allows for arbitrary code execution on systems running the OpenClaw Windows Node. This can lead to full system compromise, lateral movement within the environment, and exfiltration of sensitive data, depending on the privileges of the service account running the OpenClaw node agent.

## Recommendation

Update all instances of OpenClaw Windows Node to version 2026.7.1 or later immediately. Review audit logs for system.run command executions that contain pipe characters or command substitution syntax to identify potential prior exploitation attempts.
