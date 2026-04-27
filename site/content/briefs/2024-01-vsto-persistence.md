---
title: Persistence via Visual Studio Tools for Office (VSTO) Add-ins
slug: 2024-01-vsto-persistence
description: The Visual Studio Tools for Office (VSTO) add-ins can be abused by attackers to establish persistence in Microsoft Office applications by modifying registry keys.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - persistence
  - office
  - vsto
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Microsoft Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://twitter.com/_vivami/status/1347925307643355138
  - https://vanmieghem.io/stealth-outlook-persistence/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_persistence_office_vsto.yml
rules:
  - title: Suspicious VSTOInstaller Process Creation
    description: Detects suspicious process creations involving VSTOInstaller.exe which may indicate malicious VSTO add-in installations.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - process_creation
      - windows
  - title: Registry Modification for VSTO Add-in Persistence
    description: Detects registry modifications related to VSTO add-ins, specifically targeting the LoadBehavior value.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers can leverage Visual Studio Tools for Office (VSTO) add-ins to establish persistence within Microsoft Office applications. VSTO add-ins, designed to extend the functionality of Office applications, can be manipulated by threat actors to execute malicious code upon application startup. By modifying specific registry keys associated with VSTO add-ins, adversaries can ensure their code is loaded and executed each time an Office application is launched. This technique allows for covert and…
