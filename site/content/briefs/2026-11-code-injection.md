---
brief_id: brief-2026-11-06-code-injection
event_id: brief-2026-11-06-code-injection
revision: 1
activity_at: "2026-11-06T17:26:30Z"
title: 'OpenBMB Internet of Agents: Code injection vulnerability (CVE-2026-123675)'
slug: 2026-11-code-injection
description: OpenBMB Internet of Agents is vulnerable to remote code injection via the Code Executor Tool due to improper input sanitization in the execute_code function.
date: "2026-11-06T17:26:30Z"
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
  validation_status: Needs environment validation.
cpes:
  - cpe:2.3:a:openbmb:internet_of_agents:*:*:*:*:*:*:*:*
tags:
  - code-injection
  - vulnerability
  - rce
vendors:
  - OpenBMB
products:
  - Internet of Agents (<= 9d78e88e47160eb42ee1ee8538c05e1c2c47877a)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This manipulation of the argument filename/lang causes code injection.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-123675
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123675
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to affected Internet of Agents instances.
      owner: IT Operations
      due: 24h
      evidence: The attack can be initiated remotely.
  hunt_leads:
    - lead: Monitor for suspicious child processes (e.g., /bin/sh, python, bash) originating from the service account running the Internet of Agents.
      technique_id: T1059
      data_needed:
        - Process creation logs (Sysmon Event ID 1 or EDR process telemetry)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Code injection allows for remote code execution via the Code Executor Tool.
  mitigation_plan:
    - priority: immediate
      action: Isolate vulnerable nodes from public network access.
      owner: IT Operations
      addresses: CVE-2026-123675
      evidence: Public exploit code is available.
  gaps:
    - No vendor patch available at this time.
---

A code injection vulnerability exists in the OpenBMB Internet of Agents project, specifically within the `execute_code` function of the `im_client/agents/tools/code_executor.py` file. Remote attackers can trigger code execution by manipulating the `filename` or `lang` arguments processed by the Code Executor Tool. As of this report, the project maintainers have not responded to the initial issue disclosure, and no patched version is available. Public exploit code is currently available.

## Impact

Successful exploitation allows for arbitrary remote code execution on the system hosting the Internet of Agents component.

## Recommendation

- Perform an inventory of all instances of OpenBMB Internet of Agents in your environment.
- Restrict network access to the management and agent interfaces of Internet of Agents to trusted internal networks to mitigate remote exploitation.
- Monitor logs for unusual execution patterns or child processes spawned by the Internet of Agents service until a patch is released.
