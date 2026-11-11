---
brief_id: brief-2026-11-10-artex-agentic-ai
event_id: brief-2026-11-10-artex-agentic-ai
revision: 1
activity_at: "2026-11-10T22:28:00Z"
title: 'ARTEX: Agentic AI penetration testing framework used in the wild'
slug: 2026-11-artex-agentic-ai
description: Threat actors are utilizing the open-source ARTEX agentic AI framework to automate malicious operations including credential theft, cloud API abuse, and lateral movement.
date: "2026-11-10T22:28:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-0940
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - ai-threat
  - agentic-ai
  - artex
  - cloud-security
  - storm-0940
vendors:
  - Microsoft
  - ConnectWise
products:
  - Microsoft Graph
  - Microsoft Entra ID
  - ConnectWise Cloud Backup
  - SQL Server
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Several reported ARTEX campaigns have leveraged existing or compromised access, including stolen application credentials, consented third-party apps, and valid accounts.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Common themes include webshell and SQL Server command execution, credential theft, and attempts to move between systems.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: operators have supplied ARTEX with authentication material or compromised application credentials and used it against cloud APIs and services, such as Microsoft Graph.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: It records the assets and vulnerabilities it discovers in a graph as the test progresses.
    confidence_band: high
references:
  - https://www.sophos.com/en-us/blog/artex-attackers-apply-agentic-ai
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Audit Microsoft Entra ID for unauthorized service principal changes since September 2026
      owner: SOC
      due: 24h
      evidence: Review every credential addition and role assignment made since September 2026.
  hunt_leads:
    - lead: Identify rapid command bursts and structured output markers in command-line logs
      technique_id: T1059
      data_needed:
        - Endpoint process creation logs (Process Name, CommandLine)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Commands containing structured execution-verification markers such as MARKER123/ARTX123, particularly when combined with rapid command sequences.
  mitigation_plan:
    - priority: immediate
      action: Enforce Conditional Access policies on workload identities
      owner: IT Operations
      addresses: Cloud API abuse
      evidence: Apply Conditional Access policies to workload identities where licensing allows, restricting application sign-ins to expected locations.
---

ARTEX is an open-source, multi-agent penetration testing framework written in Go that has been adopted by threat actors for malicious operations since its public release in July 2026. The framework utilizes LLM-based planning and worker agents to automate target mapping, credential harvesting, webshell deployment, and lateral movement. It has been used against cloud services such as Microsoft Graph by leveraging stolen authentication material or compromised application credentials. The use of AI agents enables rapid execution of command sequences and repeated attempts, significantly increasing the scale, noise, and persistence of attacks.

## Attack Chain

1. Initial access via stolen application credentials, consented third-party apps, or compromised valid accounts.
2. Deployment of agentic AI framework (ARTEX) to interact with target environments.
3. Planning agents map the target environment and identify potential breach paths.
4. Worker agents execute offensive tasks including scanning and credential access.
5. Webshell deployment and command execution on target hosts (e.g., SQL Server).
6. Rapid command sequencing and repeated variants to bypass defenses and move laterally.
7. Automated recording of discovered assets and vulnerabilities in a graph structure.

## Impact

Observed impact includes the compromise of cloud backup services and financial organizations. Attackers have demonstrated the ability to conduct credential theft, webshell deployment, and lateral movement at a significantly higher scale and velocity than manual operations.

## Recommendation

- Audit service principals and enterprise applications in Microsoft Entra ID; remove unused app consents and review credential additions or role assignments since September 2026.
- Apply Conditional Access policies to workload identities to restrict application sign-ins to expected locations.
- Alert on application sign-ins that utilize scripted user agents or authentication failure rates exceeding established baselines.
- Implement automated first-response playbooks to contain attacks involving privileged access, such as revoking credentials or disabling compromised service principals.
- Hunt for temporary files following the naming pattern 'i&lt;intentID>[variant]_&lt;purpose>.&lt;ext>' (e.g., i12345_b2.ps1) and paths containing 'artx', especially within C:\Windows\Temp.
