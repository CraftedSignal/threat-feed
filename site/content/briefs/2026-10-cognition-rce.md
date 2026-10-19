---
title: Unauthenticated Remote Code Execution in Cognition
slug: 2026-10-cognition-rce
description: Cognition versions prior to 0.13.0 are vulnerable to unauthenticated remote code execution due to insecure API authentication defaults and the use of a local execution sandbox.
date: "2026-10-19T20:11:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:cognition:cognition:*:*:*:*:*:*:*:*
tags:
  - cve-2026-109437
  - remote-code-execution
  - api-security
vendors:
  - Cognition
products:
  - Cognition (< 0.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can create a session via POST /sessions... without credentials
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: causing the Deep Agents ReAct loop to run attacker-directed shell commands through the local shell backend
    confidence_band: high
cves:
  - id: CVE-2026-109437
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109437
rules:
  - title: Detects CVE-2026-109437 Exploitation - Unauthenticated Session Creation
    description: Detects unauthenticated session creation attempts targeting the Cognition API
    platform: sigma
    severity: critical
    tactics:
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
    - action: Patch Cognition to version 0.13.0 or later
      owner: IT Operations
      due: 24h
      evidence: Cognition before 0.13.0 contains an unauthenticated remote code execution vulnerability
  mitigation_plan:
    - priority: immediate
      action: Apply network egress and ingress controls to isolate Cognition API
      owner: IT Operations
      addresses: CVE-2026-109437
      evidence: shipping no authentication on its REST/SSE API
---

Cognition versions before 0.13.0 contain a critical unauthenticated remote code execution vulnerability identified as CVE-2026-109437. The flaw exists because the software defaults its agent sandbox backend to local execution and fails to enforce authentication on its REST/SSE API endpoints. An attacker can exploit this by interacting with the API to create sessions and send messages, which forces the Deep Agents ReAct loop to execute arbitrary commands. Because the system lacks authentication, these commands are executed with the privileges of the server process, leading to full system compromise. This vulnerability is particularly severe due to the ease of exploitation, requiring no prior access or credentials to the system.

## Attack Chain

1. Attacker performs discovery to identify publicly exposed Cognition API instances.
2. Attacker initiates an unauthenticated session by sending a POST request to the /sessions endpoint.
3. API accepts the request and generates a session ID without requiring authentication tokens or credentials.
4. Attacker crafts a malicious message payload intended to trigger the Deep Agents ReAct loop.
5. Attacker sends the payload to the /sessions/{id}/messages endpoint via a POST request.
6. The backend processes the message and, due to the local execution sandbox configuration, interprets the embedded ReAct commands.
7. The server process executes the attacker-provided shell commands via the local shell backend.
8. Attacker achieves remote code execution as the user account running the Cognition server process.

## Impact

Successful exploitation allows for arbitrary code execution on the server running the Cognition instance. This can lead to complete host takeover, lateral movement within the network, and exfiltration of sensitive data handled by the agent. The vulnerability affects all deployments of Cognition prior to version 0.13.0.

## Recommendation

1. Upgrade Cognition to version 0.13.0 or later immediately to patch CVE-2026-109437.
2. Implement strict network access control lists (ACLs) to ensure the Cognition REST/SSE API is not accessible from the public internet.
3. Monitor web server logs for suspicious POST requests targeting /sessions and /sessions/{id}/messages endpoints from unauthorized IP addresses.
