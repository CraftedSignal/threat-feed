---
title: COM Hijacking via Scrobj.dll Persistence
slug: 2026-09-scrobj-hijacking
description: Adversaries may achieve persistence or privilege escalation by hijacking COM object registrations associated with scrobj.dll to execute arbitrary scriptlet code.
date: "2026-09-01T12:13:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.015
    technique_name: Component Object Model Hijacking
    evidence: Adversaries may achieve persistence or privilege escalation by hijacking COM object registrations associated with scrobj.dll
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1546.015/T1546.015.md
rules:
  - title: Potential Persistence Via Scrobj.dll COM Hijacking
    description: Detects the registration of scrobj.dll as a COM object server, which is a precursor to COM hijacking or persistence via ScriptletURL.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.015
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule for COM hijacking detection
      owner: Detection Engineering
      due: 72h
      evidence: Source provides detection logic for COM hijacking
  hunt_leads:
    - lead: Search for recent changes to InprocServer32 registry keys referencing scrobj.dll
      technique_id: T1546.015
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Technique relies on registry modifications
---

COM Hijacking involves exploiting the Windows Component Object Model (COM) registry lookup mechanism to force an application to load a malicious DLL or scriptlet instead of the intended component. The scrobj.dll (Microsoft Windows Script Component) is specifically targeted by adversaries because it provides a mechanism to execute scripts defined in external files, often referenced via a ScriptletURL registry key. By modifying the InprocServer32 registry subkey for specific COM classes and pointing them to a malicious path or leveraging scrobj.dll configurations, an attacker can ensure their code executes whenever the hijacked COM object is instantiated by a system process or a user-launched application. This technique allows for stealthy persistence, as the malicious code runs under the context of the calling process, potentially bypassing application allowlisting if the host process is trusted.

## Impact

Successful exploitation results in unauthorized code execution with the privileges of the process loading the hijacked COM object. This can lead to persistent backdoor access, privilege escalation if a high-integrity process triggers the hijacked object, or the evasion of security monitoring that relies on path-based process execution controls.

## Recommendation

Detection engineering teams should monitor registry modifications targeting COM object registration hives.

* Deploy the Sigma rule below to monitor for suspicious registration of scrobj.dll as an InprocServer32 handler.
* Enable Sysmon Event ID 12 and 13 to capture registry set and value modification events.
* Establish a baseline for legitimate COM registrations in the environment and investigate outliers that reference non-standard or user-writable paths.
