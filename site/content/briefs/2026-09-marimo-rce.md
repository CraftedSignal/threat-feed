---
title: Remote Code Execution in Marimo 0.20.4
slug: 2026-09-marimo-rce
description: A Remote Code Execution vulnerability in Marimo version 0.20.4 allows attackers to achieve arbitrary command execution via a publicly available exploit.
date: "2026-09-02T14:43:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webapps
  - rce
  - vulnerability
vendors:
  - Marimo
products:
  - Marimo (0.20.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public webapps exploit has been published on Exploit-DB for Marimo 0.20.4, demonstrating a RCE vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The RCE vulnerability allows for arbitrary command execution.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52673
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory and patch all Marimo 0.20.4 instances to the latest secure version.
      owner: IT Operations
      due: 24h
      evidence: Source identifies Marimo 0.20.4 as vulnerable.
  hunt_leads:
    - lead: Search for unauthorized command execution patterns or abnormal child processes spawned by the webserver service.
      technique_id: T1059
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit achieves RCE, creating potential for post-exploitation execution.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the Marimo web application interface.
      owner: IT Operations
      addresses: RCE vulnerability in Marimo 0.20.4
      evidence: Vulnerability allows remote code execution.
---

A Remote Code Execution (RCE) vulnerability has been identified in Marimo version 0.20.4, as documented in the public exploit EDB-52673. This vulnerability allows an unauthenticated or low-privileged attacker to execute arbitrary system commands within the context of the Marimo web application. The disclosure of a functional exploit script significantly lowers the barrier to entry for adversaries to gain initial access or achieve remote execution on exposed instances. Organizations running Marimo version 0.20.4 are at elevated risk of compromise, as the vulnerability affects the core execution environment of the application.

## Impact

Successful exploitation of this vulnerability allows for complete system compromise of the host running the Marimo web application. Depending on the environment, this could lead to sensitive data exfiltration, lateral movement within the network, or deployment of additional malicious payloads. All organizations utilizing Marimo 0.20.4 in internet-facing or internal-restricted environments are potentially affected.

## Recommendation

Prioritized actions for security teams:
- Identify all instances of Marimo version 0.20.4 within the environment.
- Patch Marimo immediately to the latest available version provided by the vendor.
- Implement restrictive network access controls to ensure the Marimo web interface is not exposed to untrusted networks.
- Monitor webserver logs for anomalous POST requests or unusual patterns associated with the Marimo application endpoints.
