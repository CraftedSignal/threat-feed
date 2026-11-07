---
brief_id: brief-2026-11-07-agentexecutor-abuse
event_id: brief-2026-11-07-agentexecutor-abuse
revision: 1
activity_at: "2026-11-07T03:05:49Z"
title: 'Microsoft Intune Management Extension: Potential AgentExecutor.exe abuse'
slug: 2026-11-agentexecutor-abuse
description: The Intune management utility AgentExecutor.exe can be leveraged as a living-off-the-land binary (LOLBIN) to execute arbitrary PowerShell scripts with bypassed execution policies.
date: "2026-11-07T03:05:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - lolbin
  - windows
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Intune Management Extension
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Which can be abused as a LOLBIN to execute powershell scripts
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_agentexecutor_potential_abuse.yml
rules:
  - title: Detect AgentExecutor PowerShell Execution
    description: Detects execution of the AgentExecutor.exe binary being used to launch PowerShell scripts with potentially bypassed execution policies, excluding legitimate Intune agent activity.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to identify anomalous AgentExecutor execution
      owner: Detection Engineering
      due: 48h
      evidence: Rule prevents LOLBIN abuse of AgentExecutor
  hunt_leads:
    - lead: Search for any process executions of AgentExecutor.exe where the ParentImage is NOT the Intune Management Extension
      technique_id: T1218
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source notes AgentExecutor as a LOLBIN potential
---

AgentExecutor.exe is a component of the Microsoft Intune Management Extension used for executing remediation and management scripts. Security research indicates that this binary can be abused to launch PowerShell instances with the execution policy set to "Bypass" when specific parameters are provided, allowing for the execution of unauthorized scripts. This activity is normally associated with the parent process Microsoft.Management.Services.IntuneWindowsAgent.exe; executions originating from other parent processes or occurring with unexpected arguments should be considered suspicious.

## Impact
Unauthorized execution of PowerShell scripts on systems managed by Intune, potentially leading to privilege escalation, persistence, or code execution in the context of the management agent.

## Recommendation
- Deploy the detection rule below to identify non-standard usage of AgentExecutor.exe.
- Baseline legitimate management script activity originating from the Microsoft.Management.Services.IntuneWindowsAgent.exe parent process to minimize false positives.
- Investigate any instance of AgentExecutor.exe spawned by processes other than the primary Intune agent.
