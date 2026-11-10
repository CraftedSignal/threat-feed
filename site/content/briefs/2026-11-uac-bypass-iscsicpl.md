---
brief_id: brief-2026-11-10-uac-bypass-iscsicpl
event_id: brief-2026-11-10-uac-bypass-iscsicpl
revision: 1
activity_at: "2026-11-10T02:46:28Z"
title: 'Windows: UAC bypass via iscsicpl.exe DLL hijacking'
slug: 2026-11-uac-bypass-iscsicpl
description: An attacker can elevate privileges via a UAC bypass by performing DLL hijacking against iscsicpl.exe.
date: "2026-11-10T02:46:28Z"
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
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    subtechnique_id: T1548.002
    subtechnique_name: Bypass User Account Control
    evidence: Detects the "iscsicpl.exe" UAC bypass technique that leverages a DLL Search Order hijacking technique to load a custom DLL.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_uac_bypass_iscsicpl.yml
  - https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
  - https://web.archive.org/web/20220715014753/https://twitter.com/wdormann/status/1547583317410607110
rules:
  - title: Detect UAC Bypass via iscsicpl.exe DLL Hijacking
    description: Detects the iscsicpl.exe UAC bypass technique that leverages DLL search order hijacking to load a custom DLL from a user-controlled location.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma detection rule to the environment
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided by source
  hunt_leads:
    - lead: Search for process image loads of iscsiexe.dll originating from directories other than C:\Windows\
      technique_id: T1548.002
      data_needed:
        - Sysmon Event ID 7
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique relies on loading the DLL from a user-controlled path
---

The iscsicpl.exe utility on Windows is vulnerable to a UAC bypass technique. Attackers can exploit the DLL search order by placing a malicious 'iscsiexe.dll' in a user-controlled location, such as a temp directory, which the process will then load instead of the legitimate system DLL. This allows for arbitrary code execution with elevated privileges.

## Impact
Successful exploitation allows a low-privilege user to execute arbitrary code with elevated administrative privileges, effectively bypassing User Account Control (UAC) protections.

## Recommendation
- Deploy the provided Sigma rule to monitor for suspicious image loads.
- Audit user-writable directories for the presence of 'iscsiexe.dll'.
- Restrict write permissions in directories that are frequently searched by the system's DLL search order.
