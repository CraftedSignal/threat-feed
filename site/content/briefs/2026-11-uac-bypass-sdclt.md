---
brief_id: brief-2026-11-13-uac-bypass-sdclt
event_id: brief-2026-11-13-uac-bypass-sdclt
revision: 1
activity_at: "2026-11-13T07:49:19Z"
title: Windows User Account Control Bypass via Sdclt
slug: 2026-11-uac-bypass-sdclt
description: The sdclt.exe utility can be abused for User Account Control (UAC) bypass through the manipulation of specific registry keys associated with the application's execution path.
date: "2026-11-13T07:49:19Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - uac-bypass
  - privilege-escalation
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    subtechnique_id: T1548.002
    subtechnique_name: Bypass User Account Control
    evidence: Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe
references:
  - https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
  - https://github.com/hfiref0x/UACME
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_bypass_sdclt.yml
rules:
  - title: Detect UAC Bypass via Registry Manipulation of Sdclt.exe
    description: Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

Sdclt.exe is a Windows application that can be abused to perform a User Account Control (UAC) bypass. The technique involves modifying registry keys that the binary queries during execution. By manipulating these keys, an attacker can redirect the execution flow.

## Attack Chain

1. Manipulation of registry keys in the path of sdclt.exe.
2. Execution of sdclt.exe, resulting in the triggering of an attacker-controlled path with elevated privileges.

## Recommendation

Deploy the provided Sigma detection rule to monitor for registry modifications indicative of this technique.
