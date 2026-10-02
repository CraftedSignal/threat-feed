---
title: Vibe-Trading Unauthenticated RCE and API Exposure
slug: 2026-10-vibe-trading-rce
description: Vibe-Trading v0.1.6 contains multiple critical vulnerabilities, including unauthenticated API access, unrestricted file uploads, and a command injection chain leading to container-level RCE when the API_AUTH_KEY is unset.
date: "2026-10-02T22:49:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - HKUDS
products:
  - Vibe-Trading (v0.1.6 and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated caller with TCP access to port 8899 can execute arbitrary shell commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The LLM ReAct agent selects BashTool, which calls subprocess.run(command, shell=True) with the LLM-emitted string.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: Any unauthenticated caller can write arbitrary Python scripts, shell scripts, or YAML configuration to a known, server-returned path.
    confidence_band: high
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Set API_AUTH_KEY in the agent environment to disable unauthenticated access to the FastAPI server
      owner: IT Operations
      due: 24h
      evidence: Insecure default configuration allows unauthenticated access when API_AUTH_KEY is unset
  mitigation_plan:
    - priority: immediate
      action: Configure container security to run the process as a non-root user and restrict access to port 8899
      owner: IT Operations
      addresses: RCE vulnerability due to root execution and unauthenticated API
      evidence: Container process runs as root; API exposed on 0.0.0.0:8899
---

Vibe-Trading v0.1.6 and earlier versions are affected by several critical security flaws stemming from insecure default configurations. The application defaults to an unauthenticated state where the `API_AUTH_KEY` environment variable remains unset, causing the `require_auth()` dependency in FastAPI to return immediately without enforcing access controls. Because the application runs as root within a Docker container, this exposure provides an unauthenticated attacker with the ability to execute arbitrary shell commands via the BashTool functionality, resulting in full container takeover.

Beyond RCE, the application suffers from broken authorization on read-only endpoints, which remain accessible even when `API_AUTH_KEY` is configured. Additional vulnerabilities include an unrestricted file upload mechanism that allows attackers to write scripts (e.g., .py, .sh) to known paths, and a permissive CORS configuration that permits cross-origin requests from any local machine-served web application. These vulnerabilities, combined with the application's reliance on LLM tool-calling, present a high risk for data exfiltration and persistent malicious activity.

## Attack Chain

1. Attacker performs discovery against an exposed Vibe-Trading instance on TCP port 8899.
2. Attacker confirms the lack of authentication by executing a POST request to `/sessions` without an `Authorization` header.
3. Attacker uses the `/sessions` endpoint to create a new session and obtain a `session_id`.
4. Attacker submits a crafted message to `/sessions/{session_id}/messages` containing a natural language prompt designed to trigger the BashTool.
5. The ReAct agent selects `BashTool`, which executes `subprocess.run(command, shell=True)` using the attacker-supplied input.
6. The command executes as root (UID 0) within the container environment, granting the attacker arbitrary code execution.
7. Attacker uses the RCE primitive to exfiltrate sensitive environment variables, LLM API keys, or broker tokens stored in the container memory or file system.

## Impact

Successful exploitation leads to full container takeover and potential compromise of the host environment if proper container isolation is missing. An attacker can exfiltrate sensitive data, including LLM API keys and broker credentials used for automated trading. Given the application's functionality, this can result in unauthorized financial transactions or persistent access to the victim's trading accounts. The vulnerabilities affect all instances deployed with default settings using the provided `docker-compose.yml`.

## Recommendation

Prioritize the immediate securing of all Vibe-Trading instances by enforcing authentication.
- Set a strong `API_AUTH_KEY` in the environment configuration and ensure the application is restarted with the new settings.
- Implement a `USER` directive in the `Dockerfile` to drop privileges from root to a non-privileged user.
- Restrict network access to the API server to trusted source IP addresses using firewall rules or container network policies.
- Block or monitor all HTTP requests to the `/upload` and `/sessions` endpoints that lack valid `Authorization` headers.
