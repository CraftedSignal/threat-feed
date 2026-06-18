---
title: PraisonAI Authentication Bypass via PRAISONAI_CALL_AUTH=disabled
slug: 2026-06-praisonai-auth-bypass
description: A high-severity authentication bypass vulnerability in PraisonAI versions prior to 4.6.61 allows unauthenticated attackers to invoke any registered agent by setting the `PRAISONAI_CALL_AUTH=disabled` environment variable, potentially leading to arbitrary code execution or system compromise.
date: "2026-06-18T14:55:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - authentication-bypass
  - api-exploitation
  - misconfiguration
  - container
vendors:
  - PraisonAI
products:
  - praisonai (< 4.6.61)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1561
    technique_name: Disk Wipe
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-8ccj-p46r-jwqq
rules:
  - title: Detect PraisonAI Unauthenticated Agent Invocation
    description: Detects unauthenticated POST requests to the PraisonAI agent invocation endpoint, which could indicate exploitation of the PRAISONAI_CALL_AUTH=disabled vulnerability or reconnaissance for such misconfiguration.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1561.002
    data_sources:
      - webserver
  - title: Detect PraisonAI PRAISONAI_CALL_AUTH=disabled Misconfiguration
    description: Detects processes where `docker` or `docker-compose` commands are used to explicitly set `PRAISONAI_CALL_AUTH=disabled`, indicating a potentially vulnerable PraisonAI deployment.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1561.002
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical authentication bypass exists in PraisonAI, affecting versions prior to 4.6.61. The vulnerability stems from an undocumented "feature" where setting the `PRAISONAI_CALL_AUTH=disabled` environment variable completely deactivates authentication for the `/api/v1/agents/{id}/invoke` endpoint. This misconfiguration is highly likely to be present in production Docker and Docker Compose deployments due to the application's own error messages explicitly advertising this bypass as a convenience option. Attackers can leverage this to gain full unauthenticated access to agent invocation functionalities, enabling them to trigger any registered agent and potentially execute arbitrary actions depending on the agent's configured tools, leading to severe compromise of the host system or connected services.

## Attack Chain

1.  **Reconnaissance**: An attacker identifies an internet-facing PraisonAI instance, typically deployed via Docker or Docker Compose.
2.  **Vulnerability Identification**: The attacker attempts to interact with the `/api/v1/agents/{id}/invoke` endpoint without authentication, potentially observing error messages that suggest setting `PRAISONAI_CALL_AUTH=disabled` to bypass auth, confirming the misconfiguration.
3.  **Unauthenticated API Call**: The attacker constructs a `POST` request to `/api/v1/agents/{agent_id}/invoke` with a malicious payload, targeting a known or guessed agent ID, and sends it to the vulnerable PraisonAI instance without providing any authentication credentials.
4.  **Agent Triggering**: Due to the `PRAISONAI_CALL_AUTH=disabled` setting, the PraisonAI server bypasses all authentication checks and processes the unauthenticated request, triggering the specified agent.
5.  **Execution via Agent Tools**: The activated agent, configured with specific tools (e.g., shell access, Python interpreter, API keys), executes arbitrary actions as dictated by the attacker's payload injected via the `invoke` endpoint.
6.  **Impact**: This unauthenticated execution leads to consequences such as data exfiltration, remote code execution, system compromise, or further lateral movement within the compromised environment.

## Impact

The primary impact of this vulnerability is full unauthenticated access to the PraisonAI agent invocation API. If exploited, an attacker can trigger any registered agent on the server without needing valid credentials. This means that if an agent has been configured with access to sensitive systems or functionalities (e.g., shell command execution, database access, cloud API keys), the attacker can leverage these capabilities to execute arbitrary actions. This can result in data exfiltration, privilege escalation, remote code execution, or complete compromise of the underlying server and connected resources. The ease of exploitation and potential for severe consequences makes this a critical security concern for organizations running affected PraisonAI versions.

## Recommendation

*   Immediately update PraisonAI instances to version `4.6.61` or newer to remediate the vulnerability.
*   Review all Dockerfiles, Docker Compose configurations, and environment variable settings for PraisonAI deployments to ensure `PRAISONAI_CALL_AUTH=disabled` is not present, or is explicitly set to `enabled`.
*   Deploy the provided `Detect PraisonAI Unauthenticated Agent Invocation` Sigma rule to your SIEM to monitor for exploitation attempts against the `/api/v1/agents/{id}/invoke` endpoint.
*   Deploy the provided `Detect PraisonAI PRAISONAI_CALL_AUTH=disabled Misconfiguration` Sigma rule to your EDR/SIEM to identify systems misconfigured with the vulnerable environment variable.
*   Implement strict network access controls to limit access to PraisonAI instances, particularly the `/api/v1/agents/{id}/invoke` API endpoint, to only trusted internal networks or specific services.
