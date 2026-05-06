---
title: Craft CMS Authenticated Remote Code Execution via Malicious Attached Behavior
slug: 2024-01-craft-cms-rce
description: Craft CMS versions before 4.17.12 and 5.9.18 are vulnerable to authenticated remote code execution via malicious behavior injection in the field layout hydration path.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - craft-cms
  - rce
  - vulnerability
vendors:
  - Craft CMS
products:
  - cms (< 4.17.12)
  - cms (< 5.9.18)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://github.com/advisories/GHSA-qrgm-p9w5-rrfw
  - https://github.com/craftcms/cms/commit/ab85ca7f5f926994f723f60584054a1f4c4c5de3
rules:
  - title: Detect Craft CMS RCE Attempt via Element Search
    description: Detects potential remote code execution attempts in Craft CMS by monitoring POST requests to /admin/actions/element-search/search with suspicious JSON payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Craft CMS AttributeTypecastBehavior Injection
    description: Detects attempts to inject AttributeTypecastBehavior into Craft CMS requests, which can lead to remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Craft CMS versions before 4.17.12 and 5.9.18 are vulnerable to authenticated remote code execution. The vulnerability stems from an input-handling flaw in a Yii object creation path, allowing any authenticated user to inject malicious configuration and execute arbitrary commands on the server. This is achieved by exploiting the dynamic object configuration feature of Yii, which Craft CMS utilizes to build parts of itself from a settings list. This vulnerability is related to a previously disclosed issue (GHSA-255j-qw47-wjh5) but utilizes a different, unmitigated path. The attack exploits the condition field layouts data conversion to a live FieldLayout object without proper sanitization.

## Attack Chain

1. An authenticated user logs into the Craft CMS admin panel.
2. The attacker crafts a malicious POST request to `/admin/actions/element-search/search` with a JSON payload.
3. The JSON payload contains a `condition` parameter with a nested `fieldLayouts` array.
4. Within the `fieldLayouts` array, the attacker injects a `yii\\behaviors\\AttributeTypecastBehavior` object with a `__construct()` method.
5. The `__construct()` method contains the malicious configuration, including `attributeTypes` and `typecastBeforeSave` parameters.
6. The `typecastBeforeSave` parameter is configured to execute a shell command (e.g., using `/bin/bash -c`).
7. The server-side application processes the request and attempts to create a FieldLayout object from the provided configuration data.
8. Due to the lack of sanitization, the malicious configuration is injected during object creation, leading to the execution of the attacker-controlled command.

## Impact

Successful exploitation allows an attacker to execute arbitrary commands on the server with the privileges of the web server user. This can lead to complete compromise of the Craft CMS instance, including data theft, modification, or deletion. An attacker could also pivot to other systems on the network from the compromised server. There is no specific victim count or sector targeted mentioned, but any Craft CMS instance using a vulnerable version is susceptible.

## Recommendation

*   Upgrade Craft CMS to version 4.17.12 or 5.9.18 or later to patch the vulnerability (Affected products).
*   Deploy the Sigma rule `Detect Craft CMS RCE Attempt via Element Search` to identify exploitation attempts in web server logs (rules).
*   Monitor POST requests to `/admin/actions/element-search/search` for suspicious JSON payloads, particularly those containing `yii\\behaviors\\AttributeTypecastBehavior` (Attack Chain).
