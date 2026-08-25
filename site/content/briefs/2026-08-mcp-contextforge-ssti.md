---
title: Remote Code Execution via SSTI in mcp-contextforge-gateway
slug: 2026-08-mcp-contextforge-ssti
description: An authenticated Server-Side Template Injection (SSTI) vulnerability in mcp-contextforge-gateway version 0.9.0 and earlier allows attackers to achieve Remote Code Execution via unsandboxed Jinja2 template rendering.
date: "2026-08-25T18:49:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mcp-contextforge-gateway
  - ssti
  - rce
  - vulnerability
products:
  - mcp-contextforge-gateway
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A template that traverses to __builtins__.__import__ and calls os.popen (or any equivalent chain) executes arbitrary code at render time.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vwf3-4xxj-qg6h
rules:
  - title: Detect Exploitation of SSTI in mcp-contextforge-gateway
    description: Detects potential SSTI exploitation attempts by monitoring for malicious Jinja2 template syntax in POST requests to the prompts API endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade mcp-contextforge-gateway to >=1.0.0
      owner: IT Operations
      due: 24h
      evidence: Maintainer confirms v1.0.0+ resolves the SSTI vulnerability via SandboxedEnvironment.
    - action: Deploy SSTI detection rule
      owner: Detection Engineering
      due: 24h
      evidence: Detection rule provided in brief.
  hunt_leads:
    - lead: Search logs for registration of templates containing __builtins__ or os.popen
      technique_id: T1059.003
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: SSTI payload structure allows for clear string-based matching in logs.
  mitigation_plan:
    - priority: immediate
      action: Update to version 1.0.0
      owner: IT Operations
      addresses: mcp-contextforge-gateway < 1.0.0
      evidence: Official fix provided in v1.0.0.
---

The mcp-contextforge-gateway service, up to version 0.9.0, is vulnerable to Server-Side Template Injection (SSTI) due to the use of a plain, unsandboxed Jinja2 Environment for rendering user-supplied prompt templates. The vulnerability exists within `mcpgateway/services/prompt_service.py` in the `_render_template` method. By registering or updating a prompt template via the gateway's REST API, an authenticated user can inject arbitrary Jinja2 syntax. Because the environment does not restrict attribute traversal or function calls, an attacker can access Python built-ins such as `__builtins__.__import__` to execute arbitrary commands. This allows for full host compromise, including access to environment variables, credentials, and persistent modifications to the gateway host. This issue was resolved in version 1.0.0 by migrating to a `jinja2.sandbox.SandboxedEnvironment`.

## Attack Chain

1. Attacker obtains valid credentials for the mcp-contextforge-gateway service with permissions to register or update prompt templates.
2. Attacker crafts a malicious Jinja2 payload utilizing the `self.__init__.__globals__.__builtins__` chain to reach the `os` module.
3. Attacker submits the crafted template content to the gateway via the `POST /prompts` or `PUT /prompts/{id}` REST API endpoint.
4. The gateway stores the malicious template string in its backend database.
5. The attacker or another process triggers the `prompts/get` flow through the gateway.
6. The `PromptService.get_prompt` method calls `_render_template` with the stored, malicious template.
7. The unsandboxed `jinja2.Environment` interprets and executes the embedded Python commands at render-time.
8. The attacker achieves Remote Code Execution with the permissions of the gateway service process.

## Impact

Successful exploitation results in full host compromise under the security context of the gateway process. Attackers gain the ability to read or modify files on the gateway host, exfiltrate sensitive environment variables (e.g., API keys, database credentials), and move laterally within the network. In multi-tenant environments, a single compromised tenant account can lead to a complete takeover of the gateway, affecting all other tenants.

## Recommendation

1. Upgrade all instances of `mcp-contextforge-gateway` to version 1.0.0 or higher immediately to address the use of the unsandboxed Jinja2 environment.
2. Audit prompt templates currently stored in the gateway database for suspicious Jinja2 syntax or external references.
3. Review access logs for the `POST /prompts` and `PUT /prompts/{id}` endpoints to identify unauthorized or anomalous template registration activity.
4. Restrict permissions for registering or updating prompt templates to a limited set of trusted users to reduce the attack surface.
