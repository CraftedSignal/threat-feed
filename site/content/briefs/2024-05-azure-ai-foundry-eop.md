---
title: CVE-2026-35435 Azure AI Foundry Elevation of Privilege Vulnerability
slug: 2024-05-azure-ai-foundry-eop
description: CVE-2026-35435 is an elevation of privilege vulnerability in Azure AI Foundry M365 that allows an unauthorized attacker to elevate privileges over a network due to improper access control in published agents.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - privilege-escalation
  - cloud
vendors:
  - Microsoft
products:
  - Azure AI Foundry
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35435
rules:
  - title: Detects CVE-2026-35435 Exploitation Attempt — Suspicious Activity Targeting Azure AI Foundry Agents
    description: Detects CVE-2026-35435 exploitation attempt — Monitors for suspicious network activity indicative of privilege escalation attempts targeting Azure AI Foundry agents.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - network_connection
      - windows
  - title: Detects CVE-2026-35435 Exploitation Attempt — Monitoring access control events in cloud environment
    description: Detects CVE-2026-35435 exploitation attempt — Monitor cloud access events.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - cloudtrail
rules_count: 2
---

CVE-2026-35435 is an elevation of privilege vulnerability affecting Microsoft Azure AI Foundry M365. The vulnerability stems from improper access control within published agents, enabling an unauthorized attacker to escalate their privileges over a network. Successful exploitation of this vulnerability could allow an attacker to perform actions with elevated permissions, potentially leading to data breaches, service disruption, or unauthorized access to sensitive resources within the Azure environment. This vulnerability highlights the importance of rigorous access control mechanisms and regular security audits in cloud environments.

## Attack Chain

1. An attacker gains initial network access through compromised credentials or other means.
2. The attacker identifies an Azure AI Foundry M365 published agent with improper access control.
3. The attacker crafts a malicious request targeting the vulnerable agent.
4. Due to insufficient access control, the agent processes the malicious request without proper authorization checks.
5. The attacker leverages the agent's elevated privileges to access restricted resources.
6. The attacker escalates privileges within the network by exploiting the compromised agent.
7. The attacker gains unauthorized access to sensitive data or critical system functions.
8. The attacker maintains persistence to further compromise the environment.

## Impact

Successful exploitation of CVE-2026-35435 can lead to significant security breaches, with potential impacts including unauthorized data access, system compromise, and disruption of critical services. The affected Azure AI Foundry M365 is a component of Microsoft's cloud infrastructure. The vulnerability poses a high risk to organizations relying on Azure AI Foundry for their operations, potentially leading to financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Apply the security patch provided by Microsoft to remediate CVE-2026-35435 on all Azure AI Foundry instances immediately (references: CVE-2026-35435).
*   Implement network segmentation and access control lists (ACLs) to limit the blast radius of potential exploits (references: Attack Chain).
*   Deploy the Sigma rule provided below to detect potential exploitation attempts targeting Azure AI Foundry (references: Sigma rule).
