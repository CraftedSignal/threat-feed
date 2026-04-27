---
title: Craft CMS Authenticated Remote Code Execution via Malicious Attached Behavior
slug: 2024-01-18-craftcms-rce
description: A remote code execution vulnerability exists in Craft CMS versions 5.6.0 through 5.9.12, where any authenticated user with control panel access can exploit the vulnerability by injecting malicious behavior via the `fieldLayouts` parameter in `ElementIndexesController::actionFilterHud()` due to the unsanitized parameter being passed to `FieldLayout::createFromConfig()`.
date: "2026-03-24T16:50:42Z"
severities:
  - high
tags:
  - craftcms
  - rce
  - vulnerability
  - webserver
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://github.com/advisories/GHSA-2fph-6v5w-89hh
rules:
  - title: Craft CMS RCE Attempt via ElementIndexesController
    description: Detects attempts to exploit the Craft CMS RCE vulnerability by monitoring for HTTP requests to the /admin/element-indexes/filter-hud endpoint with the fieldLayouts parameter in the request body.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569
      - T1569.002
    data_sources:
      - webserver
      - linux
  - title: Craft CMS RCE - AttributeTypecastBehavior
    description: Detects potential RCE attempts in Craft CMS by identifying requests that may trigger the AttributeTypecastBehavior, which is involved in the exploit.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569
      - T1569.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Craft CMS versions 5.6.0 through 5.9.12 are susceptible to a remote code execution (RCE) vulnerability (CVE-2026-33157) that bypasses previous security measures implemented to prevent similar attacks. The vulnerability stems from the `ElementIndexesController::actionFilterHud()` function, where the `fieldLayouts` parameter is passed directly to `FieldLayout::createFromConfig()` without proper sanitization. Any authenticated user with control panel access (`accessCp` permission) can exploit this…
