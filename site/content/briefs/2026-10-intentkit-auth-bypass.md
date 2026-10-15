---
title: Authorization Bypass in IntentKit via Tool Registry Misvalidation
slug: 2026-10-intentkit-auth-bypass
description: IntentKit versions 2.6.3 and earlier contain an authorization bypass vulnerability allowing unauthenticated actors to execute restricted, state-changing tools by bypassing intended ToolBindingMiddleware per-request scoping.
date: "2026-10-15T02:34:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:intentkit:intentkit:*:*:*:*:*:*:*:*
vendors:
  - IntentKit
products:
  - IntentKit (<= 2.6.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An unauthenticated or public caller in WEB, API, TWITTER, or TELEGRAM contexts can exploit this by ... replaying checkpoint and history data on a reused thread.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The executor validates tool calls against the full tool registry rather than the per-request narrowed tool advertisement enforced by ToolBindingMiddleware.
    confidence_band: high
cves:
  - id: CVE-2026-76066
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76066
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade IntentKit to version > 2.6.3.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76066 affects IntentKit through 2.6.3.
  hunt_leads:
    - lead: Analyze logs for state-changing tool executions occurring outside of expected user session flows.
      technique_id: T1203
      data_needed:
        - Application transaction logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Actors can execute restricted capabilities by replaying checkpoint and history data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade IntentKit software.
      owner: IT Operations
      addresses: CVE-2026-76066
      evidence: Vulnerability in IntentKit through 2.6.3.
---

IntentKit versions 2.6.3 and earlier are affected by an authorization bypass vulnerability identified as CVE-2026-76066. The vulnerability stems from a flaw in the executor component, which validates tool calls against the global tool registry rather than the narrowed tool advertisement enforced by the ToolBindingMiddleware. This failure to validate against per-request constraints allows unauthenticated or unauthorized callers in web, API, Twitter, or Telegram contexts to invoke sensitive, state-changing tools. 

The scope of the impact includes owner-only capabilities such as financial wallet transfers, arbitrary memory writes, and unauthorized agent calls. By providing the exact tool name and associated arguments - potentially via indirect prompt injection or by replaying previously captured session history data - an actor can force the execution of restricted tools without requiring human-in-the-loop approval. This bypasses the intended security boundary of the framework, posing a high risk to data integrity and financial assets managed by the agent.

## Impact

Successful exploitation allows for unauthorized execution of sensitive agent functions. In environments where IntentKit manages financial accounts or persistent memory, this can lead to unauthorized asset transfers or data manipulation. The vulnerability is exploitable by public callers, meaning any integrated interface exposing the IntentKit executor is at risk.

## Recommendation

* Upgrade IntentKit to a version beyond 2.6.3 as soon as a patch is available.
* Audit application logs for calls to privileged state-changing tools (such as wallet transfer or memory-write) originating from public or untrusted contexts that do not coincide with expected user session checkpoints.
* Implement stricter server-side validation of tool call arguments to ensure they conform to the intended scope defined by ToolBindingMiddleware, rather than relying solely on the framework's internal registry validation.
