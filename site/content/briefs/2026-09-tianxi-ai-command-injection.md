---
title: Command Injection Vulnerability in Tianxi AI Agent PC Application
slug: 2026-09-tianxi-ai-command-injection
description: A command injection vulnerability (CVE-2026-19136) in the Tianxi AI Agent PC Application allows unauthenticated local attackers to execute arbitrary system commands via specially crafted links.
date: "2026-09-10T23:10:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tianxi:ai_agent_pc_application:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - cve
vendors:
  - Tianxi
products:
  - AI Agent PC Application
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: A potential command injection vulnerability was reported in the Tianxi AI Agent PC Application that could allow operating system commands to be executed if a local user opens a specially crafted link.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows operating system commands to be executed.
    confidence_band: high
cves:
  - id: CVE-2026-19136
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19136
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory and isolate systems running the Tianxi AI Agent PC Application
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-19136
  mitigation_plan:
    - priority: immediate
      action: Monitor for anomalous process child spawning from the application binary
      owner: SOC
      addresses: CVE-2026-19136
      evidence: Source reporting of command injection
---

CVE-2026-19136 is a command injection vulnerability identified within the Tianxi AI Agent PC Application, a software package distributed within the Chinese market. The vulnerability arises from improper validation of input handled by the application when processing user-initiated links. An attacker can leverage this flaw by inducing a local user to click a specially crafted link designed to trigger the injection of operating system commands. Successful exploitation results in the execution of arbitrary code with the privileges of the logged-in user. Defenders should prioritize auditing the application's configuration and monitoring for anomalous process spawning patterns stemming from the AI agent's execution environment.

## Impact

Successful exploitation of this vulnerability allows unauthorized command execution on the victim's machine. This can lead to full system compromise, data exfiltration, or the deployment of secondary malware payloads. The impact is categorized with a CVSS v3.1 base score of 7.8, indicating high potential for system-level damage within affected environments where the Tianxi AI Agent is deployed.

## Recommendation

- Monitor endpoint process creation logs for instances where the Tianxi AI Agent executable spawns suspicious child processes, such as cmd.exe, powershell.exe, or wscript.exe.
- Implement network-level or host-based blocks for unrecognized or suspicious URI schemes associated with the Tianxi application if they are observed as delivery vectors for malformed links.
- Review organizational software inventory to identify installations of the Tianxi AI Agent PC Application and restrict user access until a vendor-supplied security patch is verified and applied.
