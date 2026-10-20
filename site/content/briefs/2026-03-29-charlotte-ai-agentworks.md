---
brief_id: brief-2026-03-29-charlotte-ai-agentworks
event_id: brief-2026-03-29-charlotte-ai-agentworks
revision: 2
activity_at: "2026-03-29T14:22:47Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:b4d7e2f5046ee8ea3f394c61350729df0af060a92bc98b3c2361779979749181
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Charlotte AI AgentWorks for Security Automation
slug: 2026-03-29-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks introduces a platform for building and orchestrating AI-powered security agents to enhance SOC capabilities and automate security operations.
date: "2026-03-29T14:22:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - AI
  - security automation
  - agentic SOC
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Suspicious Agent Deployment
    description: Detects the deployment of new agents that may be malicious based on unusual file paths or names, indicating a potential unauthorized addition to the agent network.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
  - title: Detect Workflow Modification by Unauthorized User
    description: Detects modifications to automated workflows by users who do not typically modify such workflows, indicating potential compromise or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - integrity_procedure
    techniques:
      - T1565.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike has launched Charlotte AI AgentWorks, an ecosystem designed to facilitate the creation and deployment of AI-driven security agents. This platform aims to revolutionize security operations by enabling analysts to orchestrate context-aware agents that can reason across domains and automate tasks. The goal is to augment human analysts, not replace them, by providing an agentic security workforce capable of operating at machine speed. Charlotte AI AgentWorks integrates with leading AI models from Anthropic, NVIDIA, and OpenAI, and partners with global system integrators like Accenture, Deloitte, Kroll, Telefonica Tech, and Salesforce to build custom agents. The platform leverages the CrowdStrike Falcon platform for unified data, threat intelligence, and security guardrails. Charlotte Agentic SOAR acts as the orchestration layer, enabling the activation and coordination of agents across complex workflows while maintaining human oversight and governed access.

## Attack Chain

This threat brief describes an AI platform intended to improve security rather than an attack. Therefore, a traditional attack chain is not applicable. Instead, we can describe how an attacker might attempt to compromise or misuse the Charlotte AI AgentWorks platform itself.

1. **Initial Access (Compromised Credentials):** An attacker gains unauthorized access to the Charlotte AI AgentWorks platform through compromised user credentials, possibly via phishing or credential stuffing attacks.
2. **Privilege Escalation (Agent Impersonation):** The attacker exploits a vulnerability or misconfiguration within the platform to elevate their privileges, allowing them to impersonate a legitimate security agent.
3. **Data Access (Telemetry Manipulation):** Using elevated privileges, the attacker accesses and manipulates the unified Falcon platform telemetry data used by the AI agents, potentially injecting false positives or hiding malicious activity.
4. **Workflow Tampering (SOAR Poisoning):** The attacker modifies automated workflows within Charlotte Agentic SOAR, injecting malicious actions or disabling critical security checks.
5. **Agent Deployment (Malicious Agent Injection):** The attacker crafts and deploys a malicious security agent onto the platform, disguised as a legitimate tool or utility, which can then be used to perform unauthorized actions.
6. **Lateral Movement (Compromised Endpoints):** The malicious agent leverages its access to the Falcon platform to identify and compromise vulnerable endpoints within the organization's network, facilitating lateral movement.
7. **Impact (Data Exfiltration / System Disruption):** The attacker uses the compromised endpoints to exfiltrate sensitive data or disrupt critical systems, taking advantage of the AI platform's trust and access to perform malicious actions undetected.

## Impact

Compromise of the Charlotte AI AgentWorks platform could lead to severe consequences, including data breaches, system disruptions, and erosion of trust in the organization's security posture. Malicious actors could leverage the AI-powered agents to automate attacks, evade detection, and amplify the impact of their activities. The platform's access to sensitive data and critical systems makes it a high-value target for sophisticated adversaries.

## Recommendation

*   Implement strong multi-factor authentication (MFA) for all user accounts accessing the Charlotte AI AgentWorks platform to prevent unauthorized access via compromised credentials.
*   Enable and monitor audit logs within the Charlotte AI AgentWorks platform and the underlying CrowdStrike Falcon platform to detect suspicious activity, such as unauthorized agent deployments or workflow modifications.
*   Implement the Sigma rule "Detect Suspicious Agent Deployment" to identify potentially malicious agents being deployed on the platform (see below).
*   Regularly review and validate the integrity of automated workflows within Charlotte Agentic SOAR to prevent tampering and ensure that security checks are functioning correctly.
*   Implement the Sigma rule "Detect Workflow Modification by Unauthorized User" to detect tampering of automation workflows (see below).
*   Monitor network traffic originating from agents deployed on the platform to identify any unusual or unauthorized communication patterns.
