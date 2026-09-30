---
title: Command Injection Vulnerability in AiSOC Actions Service
slug: 2026-09-aisoc-cmd-injection
description: AiSOC versions 7.2.0 through 11.9.9 are vulnerable to authenticated command injection via unescaped parameters in the actions service, allowing arbitrary command execution with elevated privileges.
date: "2026-09-30T02:30:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aisoc:aisoc:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - rce
vendors:
  - AiSOC
products:
  - AiSOC (7.2.0 - 11.9.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated users can inject single quotes into file_path, path, script_name, or script_args parameters to break out of quoted arguments and execute arbitrary commands.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Execute arbitrary commands on managed endpoints with SYSTEM or root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-103056
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103056
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade AiSOC to version 12.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-103056 mitigation
  mitigation_plan:
    - priority: immediate
      action: Upgrade AiSOC to version 12.0.0
      owner: IT Operations
      addresses: CVE-2026-103056
      evidence: NVD vulnerability fix requirement
---

AiSOC versions 7.2.0 through 11.9.9 contain a critical command injection vulnerability within the actions service. The flaw originates from the insecure handling of action parameters in the `crowdstrike_rtr.py` and `endpoint.py` modules, where inputs such as `file_path`, `path`, `script_name`, or `script_args` are interpolated into system command strings without proper escaping. Authenticated users can provide specially crafted input containing single quotes to break out of shell argument quoting. This enables the execution of arbitrary commands with the privileges of the AiSOC service, which typically operates as SYSTEM on Windows or root on Linux/macOS. This vulnerability is particularly severe because it allows an authenticated user to gain full control over managed endpoints, potentially leading to unauthorized data access, persistence, or lateral movement within the environment.

## Impact

Successful exploitation allows an authenticated attacker to achieve arbitrary code execution on any endpoint managed by the vulnerable AiSOC agent. In enterprise environments, this represents a significant risk to host integrity, as the AiSOC service is designed to run with elevated privileges to facilitate real-time response and administrative tasks. Compromise of these endpoints can be leveraged to disable security controls, exfiltrate sensitive data, or install additional malicious tools across the network.

## Recommendation

- Upgrade all instances of AiSOC to version 12.0.0 or later immediately to patch CVE-2026-103056.
- Audit logs for the AiSOC actions service for anomalous parameter input patterns containing single quotes or shell metacharacters.
- Restrict access to the AiSOC administrative console to authorized security personnel only to mitigate the risk of authenticated exploitation.
- Implement strict input validation and command parameterization for all service-based task execution modules.
