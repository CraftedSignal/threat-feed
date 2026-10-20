---
title: Remote Code Execution in piflow DeepAgents
slug: 2026-10-piflow-rce
description: An unauthenticated remote code execution vulnerability in piflow versions 2.0.0 through 2.0.1 allows attackers to execute arbitrary system commands via the DeepAgents chat agent.
date: "2026-10-20T02:31:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:piflow:piflow:2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:piflow:piflow:2.0.1:*:*:*:*:*:*:*
tags:
  - rce
  - vulnerability
  - cve-2026-109442
vendors:
  - piflow
products:
  - piflow (2.0.0-2.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The POST /chat and POST /chat/stream endpoints lack authentication.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can instruct the agent to call the exec_shell tool, which runs arbitrary commands via subprocess.run.
    confidence_band: high
cves:
  - id: CVE-2026-109442
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109442
rules:
  - title: Detect Exploitation of CVE-2026-109442 - Unauthenticated Access to piflow Chat
    description: Detects potential exploitation attempts by monitoring unauthenticated POST requests to the piflow /chat or /chat/stream endpoints.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch piflow to a version beyond 2.0.1
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109442 vulnerability in 2.0.0 through 2.0.1
    - action: Deploy Sigma rule for /chat endpoint access
      owner: Detection Engineering
      due: 24h
      evidence: Unauthenticated POST endpoints identified in source
  mitigation_plan:
    - priority: immediate
      action: Apply WAF or firewall rules to block traffic to /chat and /chat/stream
      owner: IT Operations
      addresses: CVE-2026-109442
      evidence: Endpoints lack authentication and allow arbitrary execution
---

piflow versions 2.0.0 through 2.0.1 are affected by a critical remote code execution (RCE) vulnerability located within the DeepAgents chat agent component. The vulnerability arises because the POST /chat and POST /chat/stream endpoints lack authentication, allowing any unauthenticated remote user to interact with the agent. An attacker can manipulate the agent by instructing it to utilize the exec_shell tool. This tool executes arbitrary shell commands via Python's subprocess.run function without performing input validation, sanitization, or requiring human approval. Successful exploitation grants the attacker the ability to execute code with the permissions of the underlying web service, leading to full system compromise and the potential theft of sensitive environment variables, including LLM API keys and database credentials.

## Impact

Successful exploitation of CVE-2026-109442 allows for unauthenticated remote code execution. This could lead to a complete compromise of the host server, unauthorized access to internal services, and the exfiltration of sensitive configuration data and API keys stored within the environment, impacting the security of any infrastructure managed or connected to the piflow instance.

## Recommendation

- Upgrade piflow to a patched version beyond 2.0.1 immediately.
- Implement network-level access controls to restrict access to the piflow instance to trusted internal IP ranges until patching is complete.
- Audit environment variables and rotating secrets such as LLM API keys and database credentials if the instance was exposed to the internet.
- Monitor web server access logs for anomalous POST requests to the /chat and /chat/stream endpoints originating from untrusted sources.
