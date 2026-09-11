---
title: Unauthenticated Remote Code Execution in OmniRoute ACP
slug: 2026-09-omniroute-rce
description: OmniRoute contains a critical remote code execution vulnerability (CVE-2026-88062) in the /api/acp/agents endpoint, allowing anonymous attackers to execute arbitrary code when requireLogin is disabled.
date: "2026-09-11T18:56:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:omniroute:omniroute:*:*:*:*:*:*:*:*
tags:
  - rce
  - cve-2026-88062
  - omniroute
vendors:
  - OmniRoute
products:
  - OmniRoute (<= 3.8.50)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An anonymous remote attacker can execute commands inside the OmniRoute container with a single HTTP request.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This executes arbitrary Node.js code inside the server container, and that code can execute OS commands via child_process.execSync().
    confidence_band: high
cves:
  - id: CVE-2026-88062
references:
  - https://github.com/advisories/GHSA-hf57-cqmx-p4gr
rules:
  - title: Detect CVE-2026-88062 Exploitation - Unauthenticated ACP Agent Registration
    description: Detects exploitation of CVE-2026-88062 via suspicious POST requests to the ACP agent registration endpoint
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all OmniRoute instances to a version beyond 3.8.50
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies version 3.8.50 as the last vulnerable release.
    - action: Configure requireLogin=true on all exposed OmniRoute instances
      owner: IT Operations
      due: 24h
      evidence: Exploit relies on unauthenticated access possible only when requireLogin is false.
  hunt_leads:
    - lead: Search logs for POST requests to /api/acp/agents originating from non-authorized internal IPs
      technique_id: T1190
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Advisory confirms the vulnerability is reachable by anonymous users in specific configurations.
---

OmniRoute version 3.8.50 and earlier are affected by a critical remote code execution (RCE) vulnerability (CVE-2026-88062) within the `/api/acp/agents` endpoint. The vulnerability exists because the application accepts user-controlled `binary` and `versionCommand` parameters to register custom ACP agents. The application fails to properly validate the `versionCommand` argument, allowing an attacker to inject arbitrary JavaScript code that is executed by the server via `child_process.execFileSync` during a version probe. 

This endpoint is reachable by anonymous users if the instance has `requireLogin=false` or during the initial bootstrap phase before a management password is set. Because the endpoint lacks necessary restrictions defined in the `LOCAL_ONLY_API_PREFIXES` or `SPAWN_CAPABLE_PREFIXES` policies, the request bypasses authorization checks. An attacker can use this vulnerability to achieve full command execution within the context of the OmniRoute server container.

## Attack Chain

1. Attacker identifies a target OmniRoute instance where `requireLogin` is set to `false`, or targets a new instance during its initial setup window.
2. Attacker sends an unauthenticated `POST` request to the `/api/acp/agents` endpoint.
3. The request body contains malicious `binary` (e.g., "node") and `versionCommand` fields, where the latter includes an `-e` argument followed by arbitrary JavaScript code.
4. The OmniRoute application saves the agent definition without verifying the safety of the `versionCommand` content beyond a simple token consistency check.
5. The application automatically triggers `refreshAgentCache()`, which invokes `detectInstalledAgents()` to probe the new agent.
6. The `detectAgent()` function calls `execFileSync` to execute the attacker-provided `versionCommand` string.
7. The Node.js process executes the injected JavaScript, allowing the attacker to interact with the underlying OS via `child_process.execSync()`.

## Impact

Successful exploitation allows for unauthenticated remote code execution within the OmniRoute server container. This grants an attacker the ability to execute system commands, access environment variables, manipulate local data files (such as database backups or configuration files), and potentially move laterally within the containerized environment. This vulnerability affects all OmniRoute instances running versions 3.8.50 and earlier.

## Recommendation

Prioritized actions for detection and remediation:

- Immediately upgrade all OmniRoute instances to a version later than 3.8.50.
- Enable `requireLogin=true` and enforce strong management authentication to prevent unauthenticated access to administrative API endpoints.
- Deploy the Sigma rules below to monitor for unauthorized requests to the ACP agent registration endpoint.
- Monitor webserver logs for `POST` requests to `/api/acp/agents` originating from external or untrusted network segments.
