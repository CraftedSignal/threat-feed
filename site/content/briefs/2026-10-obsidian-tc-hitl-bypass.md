---
brief_id: brief-2026-10-23-obsidian-tc-hitl-bypass
event_id: brief-2026-10-23-obsidian-tc-hitl-bypass
revision: 1
activity_at: "2026-10-23T21:49:02Z"
title: 'Obsidian obsidian-tc: HITL confirmation bypass in tool execution (CVE-2026-115477)'
slug: 2026-10-obsidian-tc-hitl-bypass
description: A vulnerability in the obsidian-tc server allows malicious or non-compliant clients to execute destructive tool calls by echoing validly bound request states even after a human-in-the-loop confirmation is declined.
date: "2026-10-23T21:49:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Validated against source.
cpes:
  - cpe:2.3:a:obsidian:obsidian-tc:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - hitl-bypass
  - obsidian-tc
vendors:
  - Obsidian
products:
  - obsidian-tc (>= 1.13.0, <= 1.31.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A client that echoes state after a decline can execute destructive vault operations that the human explicitly refused.
    confidence_band: high
cves:
  - id: CVE-2026-115477
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-737x-cwfr-5vvc
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade obsidian-tc to version 1.31.4 or later.
      owner: IT Operations
      due: 24h
      evidence: 'Fixed in 1.31.4: the server now also requires the confirm leg response to be approved before trusting the echoed state.'
  hunt_leads:
    - lead: Monitor application logs for tool call resubmissions following a decline response in the elicitation leg.
      technique_id: T1059
      data_needed:
        - Application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: A call to a dispatch-gated tool that was offered an inputRequired confirmation could still complete after the human declined.
  mitigation_plan:
    - priority: immediate
      action: Run deployments over stdio or unset auth.jwtSecret to disable the affected HTTP path.
      owner: IT Operations
      addresses: CVE-2026-115477
      evidence: 'Workarounds: Run affected deployments over stdio, or leave auth.jwtSecret unset.'
---

A vulnerability (CVE-2026-115477) exists in the obsidian-tc server component (v1.13.0 through v1.31.3) where the server fails to properly validate human-in-the-loop (HITL) confirmation responses. When a client performs a dispatch-gated tool call, the server issues an `inputRequired` confirmation challenge. Due to a flaw in the validation logic, the server trusts the echoed `requestState` provided by the client upon resubmission as proof of approval, even if the user previously declined the action. A malicious or non-compliant client can echo this state to bypass the user's explicit refusal, allowing destructive operations such as file deletion, cross-folder moves, and frontmatter replacements.

## Impact

Successful exploitation allows for unauthorized execution of destructive vault operations that a user explicitly declined. The impact is limited to dispatch-gated tools configured with `destructive: true` or HITL floor scopes. The server cannot verify if a client actually rendered the form to the human, meaning an attacker-controlled client can simply provide an approval response regardless of human input.

## Recommendation

* Patch obsidian-tc to version 1.31.4 or later immediately.
* For environments unable to patch, transition to stdio-based deployments or unset `auth.jwtSecret` to force usage of the legacy CLI-based `elicit_token` mechanism.
* Audit logs for suspicious tool call patterns where a rejection is followed by an immediate resubmission from the same client session.
