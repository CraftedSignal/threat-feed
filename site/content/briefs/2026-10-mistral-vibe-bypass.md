---
title: CVE-2026-109429 Command Permission Gate Bypass in Mistral Vibe
slug: 2026-10-mistral-vibe-bypass
description: Mistral Vibe versions before 2.25.4 are susceptible to a command permission gate bypass that enables arbitrary command execution via the bash promptvars feature.
date: "2026-10-14T06:22:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mistral:vibe:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - bash
vendors:
  - Mistral
products:
  - Vibe (< 2.25.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft input such as embedding a command substitution within a single-quoted variable and re-expanding it with the ${var@P} prompt-transform operator.
    confidence_band: high
cves:
  - id: CVE-2026-109429
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109429
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Mistral Vibe to 2.25.4 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109429 vulnerability report
  hunt_leads:
    - lead: Search for shell command lines containing the pattern ${*@P}
      technique_id: T1059.004
      data_needed:
        - Process command line telemetry
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit relies on the ${var@P} prompt-transform operator for execution
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.25.4
      owner: IT Operations
      addresses: CVE-2026-109429
      evidence: NVD advisory
---

Mistral Vibe versions prior to 2.25.4 contain a critical security vulnerability (CVE-2026-109429) involving a command permission gate bypass. The vulnerability stems from how the application handles shell command expansion, specifically failing to sanitize input against the bash 'promptvars' feature. Attackers can bypass static analysis performed by tree-sitter-bash by embedding command substitution sequences within single-quoted variable values. By utilizing the ${var@P} prompt-transform operator, an attacker forces the bash shell to re-expand and execute the hidden command at runtime. Because static parsing only evaluates the trailing allowlisted command, the malicious command executes silently with the privileges of the agent's terminal session, leading to potential full system compromise depending on the user context of the Vibe application.

## Impact

Successful exploitation allows for unauthorized arbitrary command execution on systems running Mistral Vibe versions before 2.25.4. This bypasses existing security gates and static analysis tools, granting attackers the ability to execute code with the terminal session privileges of the Vibe agent. This risk is significant for any deployment where untrusted input is processed by the application, potentially leading to unauthorized data access, persistence, or lateral movement within the environment.

## Recommendation

* Upgrade to Mistral Vibe version 2.25.4 or later immediately to patch CVE-2026-109429.
* Audit logs for shell-based execution patterns originating from the Mistral Vibe process or its child processes.
* Monitor terminal sessions associated with the Vibe agent for unexpected process spawns involving bash prompt expansion syntax.
