---
title: Craft CMS Authenticated Remote Code Execution via Malicious Attached Behavior
slug: 2024-01-18-craftcms-rce
description: A remote code execution vulnerability exists in Craft CMS versions 5.6.0 through 5.9.12, where any authenticated user with control panel access can exploit the vulnerability by injecting malicious behavior via the `fieldLayouts` parameter in `ElementIndexesController::actionFilterHud()` due to the unsanitized parameter being passed to `FieldLayout::createFromConfig()`.
date: "2026-03-24T16:50:42Z"
type: advisory
types:
  - advisory
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

Craft CMS versions 5.6.0 through 5.9.12 are susceptible to a remote code execution (RCE) vulnerability (CVE-2026-33157) that bypasses previous security measures implemented to prevent similar attacks. The vulnerability stems from the `ElementIndexesController::actionFilterHud()` function, where the `fieldLayouts` parameter is passed directly to `FieldLayout::createFromConfig()` without proper sanitization. Any authenticated user with control panel access (`accessCp` permission) can exploit this flaw by injecting malicious behaviors into the `fieldLayouts` configuration. This oversight allows attackers to execute arbitrary code on the server, potentially leading to complete system compromise. Defenders need to implement mitigations to detect and prevent exploitation of this vulnerability.

## Attack Chain

1. An authenticated user with control panel access crafts a malicious HTTP request.
2. The request includes a `fieldLayouts` array with a configuration containing `"as <name>"` prefixed keys within the request body to the `/admin/element-indexes/filter-hud` endpoint.
3. `ElementIndexesController::actionFilterHud()` receives the `fieldLayouts` parameter.
4. The `fieldLayouts` parameter is passed to `FieldLayout::createFromConfig($config)` without sanitization.
5. `FieldLayout::createFromConfig($config)` invokes `Model::__construct($config)`, which processes each key in the configuration.
6. The `"as rce"` key triggers `Component::__set("as rce", $value)`, which leads to the instantiation of `AttributeTypecastBehavior` and its attachment to the FieldLayout via `Yii::createObject($value)`.
7. An `"on *"` key registers a wildcard event handler. Subsequently, `parent::__construct()` is called followed by `init()` -> `setTabs([])` -> `getAvailableNativeFields()` -> `trigger(EVENT_DEFINE_NATIVE_FIELDS)`.
8. The wildcard handler fires, triggering `AttributeTypecastBehavior::beforeSave()` -> `typecastAttributes()`. The vulnerability results in `$this->owner->typecastBeforeSave` being resolved via `Component::__get()` which returns the command string from the behavior's own property, finally reaching `call_user_func([ConsoleProcessus::class, 'execute'], $command)` -> `shell_exec($command)` enabling remote code execution.

## Impact

The vulnerability allows any authenticated user with control panel access to execute arbitrary code on the Craft CMS server. Successful exploitation can lead to complete system compromise, including data theft, modification, or destruction. This RCE vulnerability can have significant impacts on organizations using affected versions of Craft CMS (5.6.0 through 5.9.12).

## Recommendation

*   Deploy the Sigma rule to detect exploitation attempts by monitoring for HTTP requests to `/admin/element-indexes/filter-hud` with the `fieldLayouts` parameter in the request body (see Sigma rule "Craft CMS RCE Attempt via ElementIndexesController").
*   Apply available patches or upgrade to a non-vulnerable version of Craft CMS (versions prior to 5.6.0 or later than 5.9.12).
*   Restrict access to the control panel to only trusted users with a legitimate need, reducing the attack surface.
*   Review and audit existing Craft CMS configurations for any suspicious behavior or event injections.
*   Monitor web server logs for unusual activity related to the `ElementIndexesController` and `FieldLayout` components, focusing on POST requests containing potentially malicious configurations (see Sigma rule "Craft CMS RCE - AttributeTypecastBehavior").
