---
brief_id: brief-2026-11-05-agentscope-auth-bypass
event_id: brief-2026-11-05-agentscope-auth-bypass
revision: 1
activity_at: "2026-11-05T14:43:40Z"
title: 'AgentScope: Authentication bypass in Agent Service (CVE-2026-123024)'
slug: 2026-11-agentscope-auth-bypass
description: AgentScope versions up to 2.0.11 contain an authentication bypass vulnerability in the Agent Service component, allowing remote attackers to manipulate the X-User-ID header to gain unauthorized access.
date: "2026-11-05T14:43:40Z"
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
cpes:
  - cpe:2.3:a:agentscope-ai:agentscope:*:*:*:*:*:*:*:*
vendors:
  - agentscope-ai
products:
  - AgentScope (<= 2.0.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-123024
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123024
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory AgentScope deployments and prepare for the release of a stable patch.
      owner: IT Operations
      due: 48h
      evidence: AgentScope up to version 2.0.11 contains an authentication bypass vulnerability.
  hunt_leads:
    - lead: Inspect web server access logs for anomalous, non-standard, or missing values in the X-User-ID header directed at AgentScope endpoints.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - WAF logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Such manipulation of the argument X-User-ID leads to missing authentication.
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to validate the format or source of the X-User-ID header, or restrict access to the Agent Service.
      owner: SOC
      addresses: CVE-2026-123024
      evidence: The attack can be executed remotely.
---

A security vulnerability exists in the Agent Service component of AgentScope (versions up to 2.0.11). The issue resides in the 'get_current_user_id' function within 'src/agentscope/app/deps.py'. An attacker can bypass authentication mechanisms by manipulating the 'X-User-ID' HTTP header. Exploitation is possible remotely and public disclosure of the vulnerability has occurred. A fix via a pull request is currently pending acceptance.

## Impact

Successful exploitation allows for unauthenticated access to the Agent Service. This effectively leads to missing authentication controls for the affected endpoint.

## Recommendation

* Monitor web application logs for anomalous 'X-User-ID' header values or unauthorized access attempts to the Agent Service component.
* Inventory all instances of AgentScope within the environment and track the availability of a patch for version 2.0.11 or later.
* Until a formal patch is released, consider implementing strict ingress filtering or WAF rules to restrict access to the Agent Service endpoint.
