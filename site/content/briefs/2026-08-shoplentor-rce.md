---
title: CVE-2026-6020 Arbitrary Function Execution in ShopLentor Plugin
slug: 2026-08-shoplentor-rce
description: The ShopLentor WordPress plugin is vulnerable to authenticated remote code execution via insecure deserialization of user input in the REST API handler, allowing administrators to execute arbitrary PHP functions.
date: "2026-08-05T09:16:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - wordpress
  - cve-2026-6020
  - rce
vendors:
  - WordPress
products:
  - ShopLentor (3.3.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The handle_action() method insecurely passes the 'callback' parameter to call_user_func(), allowing authenticated administrators to execute arbitrary PHP functions.
    confidence_band: high
cves:
  - id: CVE-2026-6020
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6020
rules:
  - title: Detect CVE-2026-6020 Exploitation Attempt in ShopLentor
    description: Detects unauthorized attempts to trigger the ShopLentor custom-action REST API endpoint with a callback parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch ShopLentor plugin to latest version
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable in versions 3.3.7 and below
  mitigation_plan:
    - priority: immediate
      action: Monitor REST API traffic for /woolentoropt/v1/custom-action
      owner: SOC
      addresses: CVE-2026-6020
      evidence: Vulnerability via woolentoropt/v1/custom-action endpoint
---

The ShopLentor plugin for WordPress, specifically in versions 3.3.7 and earlier, contains a critical security flaw identified as CVE-2026-6020. The vulnerability resides in the `woolentoropt/v1/custom-action` REST API endpoint. The underlying `handle_action()` method fails to validate user-supplied input, directly passing the `callback` parameter to the PHP `call_user_func()` function without an allowlist. 

This vulnerability allows an attacker who has already obtained Administrator-level privileges on a WordPress site to execute arbitrary PHP functions on the underlying web server. By providing a malicious callback value, an authenticated attacker can achieve remote code execution, which could lead to full site compromise, exfiltration of database contents, or lateral movement within the hosting environment. Defenders should focus on auditing REST API requests for calls to this endpoint that involve sensitive PHP functions or unexpected payloads.

## Impact

Successful exploitation allows an authenticated administrator to execute arbitrary code on the server hosting the WordPress instance. This risk level is high given that it grants an attacker complete control over the application environment. Victims are limited to WordPress instances running the vulnerable ShopLentor plugin (version 3.3.7 or lower), representing a targeted set of e-commerce installations.

## Recommendation

- Update the ShopLentor plugin to the latest version immediately to patch CVE-2026-6020.
- Audit administrative access logs for the site to identify unauthorized or suspicious user account activity.
- Implement the Sigma rule below to monitor for abuse of the vulnerable API endpoint within web server access logs.
- Restrict access to the WordPress `/wp-json/` REST API namespace for non-essential administrative accounts if possible.
