---
brief_id: brief-2026-11-10-cor-profiler-persistence
event_id: brief-2026-11-10-cor-profiler-persistence
revision: 1
activity_at: "2026-11-10T03:08:55Z"
title: Persistence via COR Profiler Environment Variables
slug: 2026-11-cor-profiler-persistence
description: Attackers can achieve persistence or privilege escalation by configuring environment variables that force the .NET runtime to load a malicious profiler DLL into managed processes.
date: "2026-11-10T03:08:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - persistence
  - privilege-escalation
  - execution
  - windows
  - registry
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    subtechnique_id: T1574.012
    subtechnique_name: COR_PROFILER
    evidence: Attackers can use these variables to load a malicious DLL (a COM-based profiler) into any managed process that reads the environment.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_enabling_cor_profiler_env_variables.yml
rules:
  - title: Detect COR Profiler Environment Variable Modification
    description: Detects the creation or modification of .NET Framework and .NET Core profiler registry keys, which can be used to load arbitrary DLLs into managed processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1574.012
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM and set alerting threshold for non-developer workstations
      owner: Detection Engineering
      due: 48h
      evidence: Persistence via COR Profiler enables high-privilege execution
  hunt_leads:
    - lead: Audit current environment variables on critical servers for existing COR_PROFILER or CORECLR_PROFILER settings
      technique_id: T1574.012
      data_needed:
        - 'PowerShell Get-ChildItem Env:'
        - Registry hive inspection
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Persistence involves static registry keys that can be enumerated
  mitigation_plan:
    - priority: medium_term
      action: Implement endpoint security controls to restrict unauthorized modification of system-wide environment variable registry keys
      owner: IT Operations
      addresses: T1574.012
      evidence: Environment variable registry keys are high-value targets
---

The .NET runtime supports environment variables, specifically COR_PROFILER and CORECLR_PROFILER, to enable performance monitoring and debugging. Attackers can abuse these variables to load a malicious DLL (a COM-based profiler) into any managed process that reads the environment, enabling code execution within the context of that process. By setting these variables in the Windows Registry (e.g., in HKLM\System\CurrentControlSet\Control\Session Manager\Environment or user-specific hives), an attacker can achieve persistent execution.

## Impact

Successful exploitation allows for arbitrary code execution in the context of any managed process (including high-integrity system services) that utilizes the .NET framework, facilitating privilege escalation and persistence.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications related to .NET profiler configuration. Identify legitimate usage of profilers in your environment to minimize false positives, as these are typically used by development and troubleshooting tooling.
