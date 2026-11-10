---
brief_id: brief-2026-11-10-dotnet-etw-tampering
event_id: brief-2026-11-10-dotnet-etw-tampering
revision: 1
activity_at: "2026-11-10T02:42:12Z"
title: Detection of .NET ETW Logging Tampering via Registry
slug: 2026-11-dotnet-etw-tampering
description: Adversaries may modify specific registry keys or environment variables to disable Event Tracing for Windows (ETW) within .NET processes to blind EDR telemetry.
date: "2026-11-10T02:42:12Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Checked against Sigma source repository metadata
tags:
  - defense-impairment
  - persistence
  - windows
  - telemetry-tampering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_dot_net_etw_tamper.yml
  - https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf
rules:
  - title: Detect .NET ETW Logging Tampering
    description: Detects the disabling of ETW providers for .NET processes via registry modifications to .NETFramework keys or COMPlus environment variables.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Registry logging for the specified keys to support Event ID 4657 generation.
      owner: IT Operations
      due: 48h
      evidence: Sigma rule requires Event 4657 for detection.
  hunt_leads:
    - lead: Identify endpoints with registry modifications to .NETFramework or environment variables starting with COMPlus_.
      technique_id: T1112
      data_needed:
        - Event ID 4657
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: The technique relies on registry values which are captured by 4657.
---

Attackers can disable ETW providers for .NET applications by modifying registry keys or setting specific environment variables. This technique allows malicious code, such as loaded .NET assemblies, to execute without being recorded by security products relying on ETW for visibility. This behavior has been documented as a method to impair security monitoring and defense mechanisms.

## Impact
Disabled ETW logging in .NET processes prevents security tools from observing method calls, assembly loading, and other runtime events, significantly reducing the efficacy of detection platforms.

## Recommendation
- Deploy the provided Sigma rule to monitor for registry modifications related to .NET ETW configuration.
- Establish a baseline of legitimate modifications to these specific registry keys (e.g., during software deployment or patching) to reduce false positives.
- Implement monitoring for changes to system and user environment variables, specifically those starting with "COMPlus_".
