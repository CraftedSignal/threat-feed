---
title: PraisonAI MCP Server Origin Validation Bypass
slug: 2026-08-praisonai-csrf
description: The PraisonAI MCP HTTP server is vulnerable to unauthenticated cross-site request forgery due to an insecure prefix-based Origin header validation, allowing attackers to perform persistent prompt injection via state-changing tool calls.
date: "2026-08-25T16:02:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The attacker hosts a malicious website that, when visited, triggers unauthorized state-changing requests.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can execute arbitrary MCP tools, such as creating malicious rule files that result in persistent prompt injection.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pvph-5j39-v8qc
rules:
  - title: Detect Potential CSRF against PraisonAI MCP Server
    description: Detects unauthorized HTTP POST requests to the PraisonAI MCP endpoint where the Origin header does not exactly match expected local loopback addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch all PraisonAI installations to 4.6.58 or higher.
      owner: IT Operations
      due: 24h
      evidence: PraisonAI version vulnerability < 4.6.58
  hunt_leads:
    - lead: Search web logs for POST requests to /mcp containing suspicious Origin headers.
      technique_id: T1203
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of CSRF exploit using spoofed Origin
  mitigation_plan:
    - priority: immediate
      action: Enable API key authentication for the PraisonAI MCP server.
      owner: Security Engineering
      addresses: CVE-2026-55532
      evidence: Default configuration is vulnerable due to lack of API key authentication
---

The PraisonAI MCP HTTP-stream transport (used via `praisonai mcp serve`) implements Origin header validation using a `startswith` prefix match instead of an exact comparison. This flaw allows an attacker to host a malicious page on a domain that starts with `http://localhost` or `http://127.0.0.1` (e.g., `http://localhost.attacker.com`), bypassing the security check. Since the default configuration does not require an API key and the server processes `text/plain` requests without preflight checks, an attacker can perform blind cross-site request forgery (CSRF) against a developer's local instance. By exploiting the `praisonai.rules.create` tool, an attacker can inject malicious prompt instructions into the `~/.praison/rules` directory. Because the agent runtime automatically loads all files in this directory with "always" activation, this leads to persistent prompt injection, causing the victim's agent to execute attacker-controlled instructions during all future sessions, including potential exfiltration of SSH keys and API credentials.

## Attack Chain

1. Attacker hosts a malicious webpage on a domain starting with a whitelisted prefix (e.g., `http://localhost.attacker.com`).
2. The victim, who is running the local PraisonAI MCP server, visits the attacker-controlled page in their browser.
3. The malicious page sends an asynchronous `POST` request to `http://127.0.0.1:8080/mcp` with a forged `Origin: http://localhost.attacker.com` header.
4. The server's `_validate_origin` function incorrectly returns `True` due to the `startswith` logic, allowing the request.
5. The request uses `Content-Type: text/plain`, which the browser treats as a CORS simple request, bypassing the requirement for an `OPTIONS` preflight check.
6. The MCP server processes the request as a JSON-RPC payload without authentication, as the `--api-key` defaults to `None`.
7. The `praisonai.rules.create` tool writes an attacker-controlled Markdown file to the victim's `~/.praison/rules` directory.
8. The victim's agent runtime loads the malicious rule, which is applied to all subsequent agent tasks, resulting in persistent unauthorized execution.

## Impact

Successful exploitation results in a persistent compromise of the local agent runtime. By injecting malicious rule files, the attacker can silently alter the agent's behavior to exfiltrate sensitive local files such as `~/.ssh/id_rsa` or environment-stored API keys, delete the user's existing rules, or manipulate scheduled agent tasks. This vulnerability represents a drive-by, unauthenticated, and no-direct-network-access compromise of developer environments.

## Recommendation

* Upgrade PraisonAI to version 4.6.58 or later, where the Origin validation logic has been hardened.
* Implement explicit Origin header checks using `urllib.parse` to ensure exact scheme, host, and port matching.
* Enforce API key authentication by default for the HTTP-stream transport to prevent unauthenticated requests.
* Restrict `Content-Type` for the MCP dispatcher to `application/json` to ensure browsers require a CORS preflight for state-changing requests.
