---
title: Authorization Bypass in NousResearch hermes-agent
slug: 2026-09-hermes-agent-auth-bypass
description: An authorization bypass vulnerability in the _sess_nowait function of NousResearch hermes-agent version 0.18.0 allows remote attackers to gain unauthorized access by manipulating the session_id argument.
date: "2026-09-03T13:21:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nousresearch:hermes-agent:0.18.0:*:*:*:*:*:*:*
vendors:
  - NousResearch
products:
  - hermes-agent (0.18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-85105
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85105
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to hermes-agent endpoints
      owner: IT Operations
      due: 24h
      evidence: Authorization bypass via remote session manipulation
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate vulnerable hermes-agent instances
      owner: SOC
      addresses: CVE-2026-85105
      evidence: Vulnerability in hermes-agent 0.18.0
---

NousResearch hermes-agent version 0.18.0 contains a security flaw in the session management component, specifically within the _sess_nowait function located in s71.py. The vulnerability arises from improper validation of the session_id argument, which can be manipulated by a remote attacker to bypass authorization mechanisms. This vulnerability, tracked as CVE-2026-85105, enables unauthenticated actors to potentially hijack or interact with active sessions without valid credentials. The vendor has not responded to disclosure attempts, and no security updates are currently available to address this specific flaw. Organizations utilizing this version of hermes-agent in cloud or network-integrated environments should restrict access to the affected component to prevent unauthorized exploitation.

## Impact

Successful exploitation of this vulnerability leads to a complete authorization bypass, allowing attackers to perform actions as an authenticated user or administrative session. This poses a significant risk to data integrity and confidentiality for deployments relying on hermes-agent for session management. As the service is designed for remote interaction, the potential for widespread exploitation across internet-exposed instances is high if the affected endpoint is reachable.

## Recommendation

- Perform an inventory of all systems currently running NousResearch hermes-agent version 0.18.0.
- Implement strict network-level access controls (ACLs) or VPN requirements to prevent unauthorized remote reachability to the vulnerable session management endpoints.
- Monitor logs for unusual session activity or repeated attempts to access endpoints with manipulated session identifiers.
- If a patch or update is released, prioritize its deployment immediately due to the high severity of the authorization bypass.
