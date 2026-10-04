---
title: Remote Code Injection in InternLM MindSearch via Planner Agent
slug: 2026-10-internlm-mindsearch-code-injection
description: InternLM MindSearch version 0.1.0 is vulnerable to remote code injection via the ExecutionAction.run function, allowing attackers to execute arbitrary code on the host system.
date: "2026-10-04T09:01:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:internlm:mindsearch:0.1.0:*:*:*:*:*:*:*
tags:
  - code-injection
  - vulnerability
  - rce
vendors:
  - InternLM
products:
  - MindSearch (0.1.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument inputs leads to code injection.
    confidence_band: high
cves:
  - id: CVE-2026-105135
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105135
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to InternLM MindSearch instances
      owner: IT Operations
      due: 24h
      evidence: Publicly disclosed remote code execution vulnerability with no patch
  mitigation_plan:
    - priority: immediate
      action: Isolate or disable vulnerable MindSearch services
      owner: IT Operations
      addresses: CVE-2026-105135
      evidence: No vendor patch available
---

InternLM MindSearch version 0.1.0 contains a critical remote code injection vulnerability. The issue resides within the ExecutionAction.run function located in mindsearch/agent/graph.py, which is part of the Planner Agent component. The vulnerability is triggered by manipulating the inputs argument during the execution flow. Because the Planner Agent fails to properly sanitize this input before processing, a remote attacker can inject and execute arbitrary system commands on the host environment. This vulnerability (CVE-2026-105135) has been publicly disclosed, and given the nature of the flaw, it is trivial to exploit. The vendor has been unresponsive to disclosure efforts, and no security patches are currently available to remediate this issue.

## Impact

Successful exploitation of CVE-2026-105135 allows an unauthenticated remote attacker to gain full code execution capabilities on the host system running the MindSearch service. This may lead to total system compromise, data exfiltration, or the deployment of additional malicious payloads. Organizations deploying InternLM MindSearch 0.1.0 are at high risk until the vulnerable component is isolated or updated.

## Recommendation

1. Inventory all instances of InternLM MindSearch 0.1.0 within the environment and restrict network access to these services until a vendor patch is available.
2. Implement strict input validation or web application firewall (WAF) rules to inspect the inputs argument passed to the Planner Agent's ExecutionAction.run function.
3. Monitor process creation logs for unexpected child processes originating from the MindSearch service process (e.g., cmd.exe, /bin/sh, /bin/bash).
