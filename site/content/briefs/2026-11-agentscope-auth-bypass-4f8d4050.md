---
brief_id: brief-2026-11-05-agentscope-auth-bypass-4f8d4050
event_id: brief-2026-11-05-agentscope-auth-bypass-4f8d4050
revision: 1
activity_at: "2026-11-05T16:20:55Z"
title: 'AgentScope: Incorrect authorization in Bash Tool (CVE-2026-123023)'
slug: 2026-11-agentscope-auth-bypass-4f8d4050
description: AgentScope versions 2.0.8 and earlier contain an authorization flaw in the Bash Tool component that allows remote attackers to bypass permission checks and execute unauthorized commands.
date: "2026-11-05T16:20:55Z"
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
  validation_status: Needs environment validation of AgentScope version
cpes:
  - cpe:2.3:a:agentscope-ai:agentscope:*:*:*:*:*:*:*:*
vendors:
  - agentscope-ai
products:
  - AgentScope (<= 2.0.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: This affects the function check_permissions of the file src/agentscope/tool/_builtin/_bash.py of the component Bash Tool.
    confidence_band: high
cves:
  - id: CVE-2026-123023
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123023
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch AgentScope to version 2.0.9
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 2.0.9 mitigates this issue.
  hunt_leads:
    - lead: Identify systems running AgentScope versions <= 2.0.8
      data_needed:
        - Software inventory logs
        - Package manager manifests
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A flaw has been found in agentscope-ai AgentScope up to 2.0.8.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AgentScope to 2.0.9
      owner: IT Operations
      addresses: CVE-2026-123023
      evidence: Upgrading to version 2.0.9 mitigates this issue.
---

A vulnerability exists in the `check_permissions` function within `src/agentscope/tool/_builtin/_bash.py` of the AgentScope Bash Tool. The vulnerability is caused by incorrect authorization logic, which can be exploited remotely to perform unauthorized actions. A public exploit is available. This issue is resolved in version 2.0.9.

## Impact
Successful exploitation allows a remote attacker to bypass intended authorization constraints, resulting in unauthorized command execution via the affected Bash tool component.

## Recommendation
- Upgrade AgentScope to version 2.0.9 or later immediately.
- Audit logs for instances of the AgentScope Bash Tool execution to identify unauthorized access attempts.
- If upgrading is not immediately possible, restrict network access to environments hosting AgentScope instances.
