---
title: Unauthenticated RCE in DB-GPT via Insecure Mock Authentication
slug: 2026-10-db-gpt-rce
description: DB-GPT versions 0.8.2 and earlier contain an unauthenticated remote code execution vulnerability in the ReAct agent endpoint that allows attackers to execute arbitrary system commands as root.
date: "2026-10-20T02:31:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:db_gpt:db_gpt:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
  - container-security
vendors:
  - DB-GPT
products:
  - DB-GPT (<= 0.8.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: DB-GPT through 0.8.2 contains an unauthenticated remote code execution vulnerability because the /api/v1/chat/react-agent endpoint relies on a mock get_user_from_headers function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Unauthenticated attackers can send prompts that make the ReAct agent... shell_interpreter tools run arbitrary... bash as root.
    confidence_band: high
cves:
  - id: CVE-2026-77932
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77932
rules:
  - title: Detects CVE-2026-77932 Exploitation - Unauthenticated RCE via ReAct Agent
    description: Detects potential RCE attempts against the /api/v1/chat/react-agent endpoint by inspecting for command injection signatures in POST requests.
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
  immediate_actions:
    - action: Patch DB-GPT to a version later than 0.8.2
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-77932 advisory
  hunt_leads:
    - lead: Inspect web logs for anomalous POST requests to /api/v1/chat/react-agent
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability endpoint identification
---

DB-GPT versions through 0.8.2 are vulnerable to an unauthenticated remote code execution (RCE) flaw originating from an insecure implementation of the `get_user_from_headers` function. This function serves as a mock authentication mechanism, incorrectly assigning the "admin" role to every incoming request regardless of provided headers. 

The vulnerability is exposed via the `/api/v1/chat/react-agent` endpoint. Attackers can leverage this misconfiguration to interact with the ReAct agent, specifically utilizing the `code_interpreter` and `shell_interpreter` tools. Because these tools operate in an unsandboxed environment within the webserver container, they permit the execution of arbitrary Python or bash commands with root-level privileges. An attacker successful in exploiting this vulnerability can gain full control over the container, access sensitive application data, or interact with the bundled database using default administrative credentials.

## Impact

Successful exploitation results in full remote code execution within the DB-GPT webserver container. Attackers can achieve complete system compromise, exfiltrate data from the bundled database, or move laterally if the container lacks sufficient network segmentation. This vulnerability is particularly critical for deployments exposed to untrusted networks.

## Recommendation

* Immediately upgrade to a patched version of DB-GPT that addresses CVE-2026-77932 and removes the mock `get_user_from_headers` function.
* Restrict network access to the `/api/v1/chat/react-agent` endpoint to authorized internal segments only using a Web Application Firewall (WAF) or ingress controller rules.
* Audit logs for suspicious HTTP POST requests directed at `/api/v1/chat/react-agent` containing shell metacharacters or unauthorized Python code patterns.
* Implement strict resource limits and user privilege isolation for the DB-GPT container to minimize the impact of a potential container breakout or compromise.
