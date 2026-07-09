---
title: Craft CMS RCE via Missing cleanseConfig in FieldsController
slug: 2026-07-craftcms-rce-ghsa
description: An authenticated administrator in Craft CMS (versions 5.5.0 to 5.9.13) is vulnerable to Remote Code Execution (RCE) via a missing input sanitization vulnerability in the `actionRenderCardPreview()` method of `FieldsController`, allowing Yii2 event handler injection through specially crafted `fieldLayoutConfig` POST parameters, which enables arbitrary PHP code execution and sensitive information disclosure.
date: "2026-07-09T13:46:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - web-application
  - cms
  - craft-cms
  - php
vendors:
  - Craft CMS
products:
  - Craft CMS (>= 5.5.0, <= 5.9.13)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This allows Yii2 event handler injection via `on eventName` keys in the config array, leading to arbitrary code execution...During `Component::init()`, the `init` event is triggered, calling `phpinfo()`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-86vw-x4ww-x467
rules:
  - title: Detect Craft CMS RCE Attempt via FieldsController - GHSA-86vw-x4ww-x467
    description: Detects exploitation attempts against Craft CMS CVE GHSA-86vw-x4ww-x467 - POST request to render-card-preview endpoint with Yii2 event handler injection via fieldLayoutConfig parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability (GHSA-86vw-x4ww-x467) has been identified in Craft CMS, affecting versions 5.5.0 through 5.9.13, that allows authenticated administrators to achieve Remote Code Execution (RCE). The `actionRenderCardPreview()` method within the `FieldsController` component incorrectly passes the `fieldLayoutConfig` POST parameter directly to `Fields::createLayout()` without invoking `Component::cleanseConfig()`. This oversight permits attackers to inject malicious Yii2 event handlers through `on eventName` keys in the configuration array, leading to arbitrary PHP function execution. The impact extends to information disclosure, potentially exposing sensitive data like database credentials and `CRAFT_SECURITY_KEY` via `phpinfo()` output, posing a significant risk of full system compromise for affected installations.

## Attack Chain

1. An attacker obtains or compromises legitimate administrative credentials for a Craft CMS instance.
2. The authenticated attacker crafts a malicious HTTP POST request targeting the `/admin/actions/fields/render-card-preview` endpoint.
3. The request includes a `fieldLayoutConfig` POST parameter containing a specially formed `on+init` key, such as `fieldLayoutConfig[on+init]=phpinfo`.
4. The vulnerable `actionRenderCardPreview()` method processes this parameter without proper sanitization.
5. When the `FieldLayout` object is constructed, Yii2 interprets the `on init` key as an event handler registration.
6. During the `Component::init()` execution, the registered `init` event is triggered, leading to the execution of the attacker-supplied PHP function (e.g., `phpinfo()`).
7. The server responds with the output of the executed PHP function, potentially disclosing sensitive environment variables, system information, and configuration secrets, or executing arbitrary commands.

## Impact

Successful exploitation allows an authenticated administrator to achieve full Remote Code Execution (RCE) on the Craft CMS server. This can lead to complete compromise of the web server and its underlying data, including the exfiltration of sensitive information such as database credentials and the `CRAFT_SECURITY_KEY`. The ability to execute arbitrary PHP functions allows for a wide range of malicious activities, from defacement and data manipulation to establishing persistent backdoors and escalating privileges within the hosting environment. While requiring existing admin access, the severity of the code execution and information disclosure capabilities represents a critical risk.

## Recommendation

* Immediately update Craft CMS installations to a patched version beyond 5.9.13 to remediate GHSA-86vw-x4ww-x467.
* Deploy the Sigma rules in this brief to your SIEM to detect exploitation attempts against `/admin/actions/fields/render-card-preview`.
* Monitor web server access logs for requests to `/admin/actions/fields/render-card-preview` containing unusual or suspicious query parameters.
* Implement strong authentication mechanisms, such as multi-factor authentication (MFA), for all Craft CMS administrator accounts to prevent credential compromise.
* Review the `references` URL for the official advisory and patching instructions from Craft CMS.
