---
title: Weaponization of Google Vertex AI Agents
slug: 2026-04-vertex-ai-compromise
description: Researchers demonstrated that AI agents built on Google's Vertex AI can be compromised to exfiltrate data, create backdoors, and compromise infrastructure by abusing excessive permissions of the Per-Project, Per-Product Service Agent (P4SA).
date: "2026-04-01T07:43:16Z"
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

Palo Alto Networks researchers have detailed their analysis of Google Cloud Platform’s Vertex AI, specifically focusing on the Vertex Agent Engine and the Agent Development Kit (ADK). The research demonstrates how AI agents built on this platform can be weaponized. The core issue revolves around the Per-Project, Per-Product Service Agent (P4SA), which is associated with user-deployed AI agents. The researchers found that the default permissions of P4SA are excessive, allowing attackers to…
