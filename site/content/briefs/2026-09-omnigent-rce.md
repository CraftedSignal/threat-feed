---
title: Omnigent Shared Agent Bundle Overwrite Leads to Runner RCE
slug: 2026-09-omnigent-rce
description: An improper access control vulnerability in Omnigent allows authenticated users to overwrite shared agent bundles, enabling arbitrary command execution on runner infrastructure via malicious MCP server configuration.
date: "2026-09-03T00:02:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:omnigent:omnigent:*:*:*:*:*:*:*:*
vendors:
  - Omnigent
products:
  - Omnigent (< 0.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By adding a stdio MCP server to the shared agent, the attacker can cause future runner sessions using that shared agent to start an attacker-controlled command.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'The vulnerable endpoint is the full agent bundle upload route: PUT /sessions/{session_id}/agent'
    confidence_band: high
cves:
  - id: CVE-2026-62674
    cvss: 9
    epss: 0.00343
references:
  - https://github.com/advisories/GHSA-jrrm-9hc7-2v3h
rules:
  - title: Detect Potential CVE-2026-62674 Exploitation - Agent Bundle Overwrite
    description: Detects authenticated PUT requests to the agent bundle upload endpoint, which may indicate exploitation of CVE-2026-62674.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade all Omnigent installations to 0.3.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Source advisory states versions < 0.3.0 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Omnigent 0.3.0
      owner: IT Operations
      addresses: CVE-2026-62674
      evidence: Source advisory recommends version 0.3.0 as the fix.
---

Omnigent versions prior to 0.3.0 are vulnerable to an authenticated Remote Code Execution (RCE) flaw due to insufficient validation of shared/template agents. The endpoint `PUT /sessions/{session_id}/agent` allows authenticated users to upload full agent bundles. While the application UI and secondary endpoints correctly identify shared/template agents (where `agent.session_id` is `None`) as read-only and block modification, the primary bundle upload route fails to enforce this check.

By submitting a crafted bundle to this endpoint, an attacker can overwrite the global configuration of a shared agent. If the uploaded bundle includes a `stdio` MCP server configuration, the Omnigent runner process will execute the defined command as a subprocess whenever that shared agent is invoked by any user session. This effectively weaponizes shared infrastructure to execute arbitrary code with the runner's system permissions.

## Attack Chain

1. Attacker authenticates to the Omnigent platform with valid user credentials.
2. Attacker initiates an update request to the `PUT /sessions/{session_id}/agent` endpoint for their current session.
3. Attacker submits a maliciously crafted agent bundle containing a `stdio` MCP server configuration that references an attacker-supplied command.
4. The backend API fails to validate if the bound agent is a read-only shared/template agent.
5. The server overwrites the global agent configuration in the data store with the malicious bundle.
6. A victim or administrator initiates a new session using the poisoned shared/template agent.
7. The Omnigent runner environment processes the agent bundle and attempts to initialize the `stdio` MCP server.
8. The runner process spawns the attacker-specified command as a subprocess, resulting in remote code execution on the runner host.

## Impact

Successful exploitation allows an attacker to execute arbitrary code on Omnigent runner hosts with the permissions of the runner process. This enables unauthorized file access, credential theft, modification of workspace data, and potential lateral movement into internal services reachable by the runner. Because shared agents are often used by multiple users, a single successful poisoning can compromise sessions across an entire organization.

## Recommendation

Upgrade all instances of Omnigent to version 0.3.0 or later immediately to patch the validation logic in the agent bundle upload process. As a temporary compensatory control, monitor server logs for high-frequency or unauthorized access to the `PUT /sessions/{session_id}/agent` endpoint by non-administrative users.
