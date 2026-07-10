---
title: Paperclip Privilege Escalation via Agent API Key
slug: 2024-01-paperclip-privesc
description: A privilege escalation vulnerability in Paperclip allows an attacker with an Agent API key to execute arbitrary OS commands on the Paperclip server host by injecting commands into the `adapterConfig.workspaceStrategy.provisionCommand` field via the `/agents/:id` API endpoint, leading to remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - remote-code-execution
  - paperclip
vendors:
  - Paperclip
products:
  - Paperclip
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-265w-rf2w-cjh4
rules:
  - title: Detect Paperclip Agent Configuration Modification
    description: Detects modifications to the agent configuration via the API endpoint, specifically looking for changes to the workspaceStrategy.provisionCommand.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Paperclip Command Execution via Workspace Provisioning
    description: Detects command execution via /bin/sh -c during workspace provisioning, indicating potential exploitation of the vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A privilege escalation vulnerability exists in Paperclip, a workflow automation and orchestration tool. The vulnerability stems from insufficient validation of agent configuration updates. An attacker possessing a valid Agent API key can exploit this flaw to achieve arbitrary OS command execution on the Paperclip server host. Specifically, by sending a PATCH request to the `/api/agents/:id` endpoint, the attacker can modify the `adapterConfig.workspaceStrategy.provisionCommand` field, injecting malicious shell commands. When the server subsequently executes the workspace provisioning routine, these injected commands are executed, bypassing the intended trust boundary between agent runtime configuration and server host execution. The vulnerability affects Paperclip versions prior to 2026.416.0. Successful exploitation leads to remote code execution on the server host, potentially allowing attackers to compromise the entire deployment environment.

## Attack Chain

1.  The attacker obtains a valid Agent API key through legitimate means or compromise.
2.  The attacker sends a `PATCH` request to the `/api/agents/:id` endpoint, targeting a specific agent.
3.  The `PATCH` request modifies the agent's `adapterConfig`, specifically injecting a malicious command into the `adapterConfig.workspaceStrategy.provisionCommand` field. For example: `echo PAPERCLIP_RCE > poc_rce.txt`.
4.  The attacker triggers workspace provisioning by sending a `POST` request to the `/api/agents/:id/wakeup` endpoint.
5.  The Paperclip server executes the workspace provisioning routine, which includes running the command specified in `adapterConfig.workspaceStrategy.provisionCommand`.
6.  The server executes the injected command using `/bin/sh -c`, effectively running arbitrary shell commands on the host.
7.  The injected command executes successfully, for example creating a file `poc_rce.txt` on the server filesystem.
8.  The attacker gains remote code execution on the Paperclip server host, enabling them to read environment variables, exfiltrate secrets, or establish a reverse shell.

## Impact

Successful exploitation of this vulnerability grants an attacker the ability to execute arbitrary commands on the Paperclip server, potentially leading to a full compromise of the deployment environment. Since Paperclip orchestrates multiple agents and repositories, attackers could read environment variables, exfiltrate secrets, modify repositories, access database credentials, execute reverse shells, and establish persistence on the host. The vulnerability allows a malicious agent to escape the orchestration layer and gain complete control over the server.

## Recommendation

*   Deploy the Sigma rule `Detect Paperclip Agent Configuration Modification` to detect unauthorized modifications to the agent configuration via the API.
*   Apply the suggested minimal patch by implementing a server-side check to reject modifications to `adapterConfig.workspaceStrategy.provisionCommand` when the request is authenticated using an Agent API key, as detailed in the "Minimal Patch Suggestion" section of the advisory.
*   Monitor process creation events for the execution of `/bin/sh -c` with command line arguments that originate from Paperclip agent configurations using the Sigma rule `Detect Paperclip Command Execution via Workspace Provisioning`.
*   Upgrade to Paperclip version 2026.416.0 or later to patch the vulnerability.
