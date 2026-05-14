---
title: FlowiseAI Authenticated Remote Code Execution via NodeVM Sandbox Escape
slug: 2026-05-flowiseai-rce
description: FlowiseAI is vulnerable to authenticated remote code execution (RCE) due to a missing route-level authorization in the `/api/v1/node-custom-function` endpoint, allowing any authenticated user to execute arbitrary JavaScript and escape the NodeVM sandbox to run system commands.
date: "2026-05-14T14:59:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - sandbox-escape
  - nodevm
vendors:
  - FlowiseAI
products:
  - flowise <= 3.1.1
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-9rvc-vf7m-pgm2
rules:
  - title: FlowiseAI NodeVM Sandbox Escape Attempt
    description: Detects attempts to exploit FlowiseAI NodeVM sandbox escape by identifying the use of the `Error` object and constructor chain manipulation within the Custom JS Function node.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - linux
  - title: FlowiseAI Custom Function RCE via API
    description: Detects HTTP requests to the /api/v1/node-custom-function endpoint with suspicious JavaScript payloads containing potentially malicious code execution patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI, a low-code platform for building AI orchestration flows, is vulnerable to authenticated remote code execution (RCE) affecting versions 3.1.1 and earlier. The vulnerability stems from a missing authorization check on the `/api/v1/node-custom-function` endpoint, enabling any authenticated user or API key holder to submit malicious JavaScript code to the `Custom JS Function` node. When the `E2B_APIKEY` environment variable is not configured, the platform falls back to a `NodeVM` sandbox. Attackers can escape this sandbox, gain access to the host's `process` object, and execute arbitrary system commands. This allows attackers to compromise the Flowise server, potentially leading to data breaches, service disruption, or further lateral movement within the network. Most self-hosted instances are affected because the NodeVM sandbox is enabled by default when `E2B_APIKEY` is not explicitly set.

## Attack Chain

1. An attacker authenticates to the FlowiseAI application using valid credentials or a valid API key.
2. The attacker crafts a malicious JavaScript payload designed to escape the NodeVM sandbox.
3. The attacker sends an HTTP POST request to the `/api/v1/node-custom-function` endpoint, including the malicious JavaScript code in the `javascriptFunction` parameter within the request body.
4. The server, lacking proper authorization checks, executes the attacker-supplied JavaScript code within the Custom JS Function node.
5. The malicious JavaScript exploits an exception path within the NodeVM to escape the sandbox, gaining access to the host's `process` object and `child_process` module.
6. The attacker uses the `child_process` module to execute arbitrary system commands on the Flowise server. For example, `cp.execSync('id').toString().trim()` to get the user ID.
7. The attacker retrieves the output of the executed command and potentially uses it to gather sensitive information or further compromise the system.
8. The attacker leverages the compromised server for lateral movement, data exfiltration, or other malicious activities.

## Impact

Successful exploitation allows any authenticated Flowise user to execute arbitrary commands on the Flowise server. This can lead to a full compromise of the server, including the ability to read environment variables and secrets, access the filesystem, and make outbound network requests. The default configuration, which relies on the vulnerable NodeVM sandbox when `E2B_APIKEY` is not configured, increases the attack surface, as the majority of self-hosted Flowise instances are likely affected. A successful attack can result in data breaches, service disruption, and further exploitation of the compromised environment.

## Recommendation

*   Deploy the "FlowiseAI NodeVM Sandbox Escape Attempt" Sigma rule to detect attempts to exploit this vulnerability by identifying the use of the `Error` object and constructor chain manipulation within the `Custom JS Function` node.
*   Deploy the "FlowiseAI Custom Function RCE via API" Sigma rule to detect HTTP requests to the `/api/v1/node-custom-function` endpoint with suspicious JavaScript payloads containing potentially malicious code execution patterns.
*   Immediately apply the recommended remediation steps: add explicit permission gating to `/api/v1/node-custom-function`, fail closed if `E2B_APIKEY` is absent, and restrict this endpoint from generic API key access.
