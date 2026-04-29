---
title: Weaponization of Google Vertex AI Agents
slug: 2026-04-vertex-ai-compromise
description: Researchers demonstrated that AI agents built on Google's Vertex AI can be compromised to exfiltrate data, create backdoors, and compromise infrastructure by abusing excessive permissions of the Per-Project, Per-Product Service Agent (P4SA).
date: "2026-04-01T07:43:16Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Palo Alto Networks Researchers (simulated)
tags:
  - cloud
  - ai
  - vertex-ai
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1105
    technique_name: Remote File Copy
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: 'Credentials from Password Stores: Cloud Instance Metadata API'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069.002
    technique_name: 'Permission Groups Discovery: Cloud Groups'
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.006
    technique_name: 'Remote Services: Cloud Services'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114.001
    technique_name: 'Email Collection: Local Email Collection'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://www.securityweek.com/google-addresses-vertex-security-issues-after-researchers-weaponize-ai-agent/
rules:
  - title: GCP Container Image Download After Potential Vertex AI Compromise
    description: Detects attempts to download container images from private repositories after potential P4SA compromise in Google Cloud Platform.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.006
    data_sources:
      - cloudtrail
      - gcp
  - title: GCP Access to Artifact Registry After Potential Vertex AI Compromise
    description: Detects access to Artifact Registry repositories after a potential compromise of Vertex AI agents.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1069.002
    data_sources:
      - cloudtrail
      - gcp
rules_count: 2
---

Palo Alto Networks researchers have detailed their analysis of Google Cloud Platform’s Vertex AI, specifically focusing on the Vertex Agent Engine and the Agent Development Kit (ADK). The research demonstrates how AI agents built on this platform can be weaponized. The core issue revolves around the Per-Project, Per-Product Service Agent (P4SA), which is associated with user-deployed AI agents. The researchers found that the default permissions of P4SA are excessive, allowing attackers to gain unauthorized access to the Google project hosting Vertex AI. This exploitation enables malicious activities such as data exfiltration, backdoor creation, and broader infrastructure compromise. Google has since revised its documentation and recommends using Bring Your Own Service Account (BYOSA) to enforce least-privilege execution, mitigating the identified risks.

## Attack Chain

1.  An attacker gains initial access to an AI agent built on Vertex AI.
2.  The attacker exploits the excessive default permissions associated with the Per-Project, Per-Product Service Agent (P4SA).
3.  The attacker obtains the GCP service agent's credentials by abusing the P4SA permissions.
4.  Using the compromised credentials, the attacker moves from the AI agent's execution context into the owner's Google Cloud project.
5.  The attacker gains unrestricted access to the Google project hosting Vertex AI.
6.  The attacker downloads container images from private repositories that form the core of the Vertex AI Reasoning Engine.
7.  The attacker accesses restricted Artifact Registry repositories containing other images.
8.  The attacker identifies and manipulates a file within the agent's environment to achieve remote code execution and establish a persistent backdoor.

## Impact

The successful exploitation of Vertex AI agents allows attackers to exfiltrate sensitive data, establish persistent backdoors, and potentially compromise the entire Google Cloud project. This can lead to exposure of Google's intellectual property through access to the Vertex AI Reasoning Engine's container images. Furthermore, attackers can gain access to restricted Artifact Registry repositories and Google Cloud Storage buckets containing potentially sensitive information. The impact includes data breaches, intellectual property theft, and potential disruption of critical services running on the compromised infrastructure.

## Recommendation

*   Implement Bring Your Own Service Account (BYOSA) for Agent Engine to enforce the principle of least privilege, as recommended by Google.
*   Monitor service account activity within Google Cloud Platform for anomalous behavior indicative of credential compromise and lateral movement.
*   Deploy the Sigma rule to detect attempts to download container images from private repositories after potential P4SA compromise.
