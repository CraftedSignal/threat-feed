---
brief_id: brief-2026-11-10-winget-admin-tampering
event_id: brief-2026-11-10-winget-admin-tampering
revision: 1
activity_at: "2026-11-10T03:09:44Z"
title: Winget Admin Settings Modification
slug: 2026-11-winget-admin-tampering
description: Modification of Windows AppInstaller (winget) administrative settings via registry changes can be used to weaken security controls, such as enabling local manifest installations or disabling installer hash checks.
date: "2026-11-10T03:09:44Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.persistence
  - attack.defense-impairment
references:
  - https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
  - https://github.com/microsoft/winget-cli/blob/02d2f93807c9851d73eaacb4d8811a76b64b7b01/src/AppInstallerCommonCore/Public/winget/AdminSettings.h#L13
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_winget_admin_settings_tampering.yml
rules:
  - title: Winget Admin Settings Modification
    description: Detects changes to the AppInstaller (winget) admin settings, such as enabling local manifest installations or disabling installer hash checks.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
      - persistence
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

Adversaries may modify registry keys associated with the Windows AppInstaller (winget) to lower security thresholds. These modifications can enable the installation of packages from local manifests or disable mandatory installer hash checks. This behavior is associated with defense impairment and persistence.
