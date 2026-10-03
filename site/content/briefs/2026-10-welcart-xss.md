---
title: Stored Cross-Site Scripting in Welcart e-Commerce Plugin
slug: 2026-10-welcart-xss
description: An unauthenticated stored Cross-Site Scripting vulnerability in the Welcart e-Commerce WordPress plugin allows attackers to inject malicious scripts via settlement notification parameters.
date: "2026-10-03T06:54:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:welcart:e_commerce:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - Welcart
products:
  - Welcart e-Commerce (<= 2.12.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The IPN endpoint accepts the 'rel' and 'option' parameters with no authentication, nonce validation, or signature verification.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-87091
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87091
rules:
  - title: Detects CVE-2026-87091 Exploitation - Stored XSS in Welcart IPN
    description: Detects unauthenticated HTTP POST requests targeting the Welcart IPN endpoint with script-related payloads in the rel or option parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update Welcart e-Commerce plugin to the latest version immediately
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to, and including, 2.12.2
  mitigation_plan:
    - priority: immediate
      action: Upgrade Welcart e-Commerce to a patched release
      owner: IT Operations
      addresses: CVE-2026-87091
      evidence: Vulnerability exists in 2.12.2 and below
---

The Welcart e-Commerce plugin for WordPress, in versions up to and including 2.12.2, is vulnerable to a Stored Cross-Site Scripting (XSS) attack. The vulnerability originates in the plugin's Instant Payment Notification (IPN) endpoint, which fails to adequately sanitize the 'rel' and 'option' parameters. Crucially, this endpoint lacks authentication, nonce validation, and signature verification, permitting unauthenticated attackers to submit crafted payloads directly to the application. These payloads are stored within the database and are subsequently executed within the browser context of an administrator when they access the settlement error log view within the WordPress dashboard. This vulnerability poses a significant risk to administrative account security, as successful exploitation could lead to session hijacking or the unauthorized execution of actions within the WordPress environment.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator's session. This can lead to full account compromise, unauthorized configuration changes, or the exfiltration of sensitive site data. The target sector includes any organization utilizing the affected Welcart e-Commerce plugin version for WordPress operations.

## Recommendation

Update the Welcart e-Commerce plugin to the latest version, which includes patches for input sanitization and verification of IPN parameters. Until patching is completed, implement strict access controls on the IPN endpoint or monitor web server access logs for anomalous POST requests directed at the settlement notification paths.

## Detection

Detect attempts to exploit CVE-2026-87091 by monitoring for HTTP POST requests to the plugin's IPN endpoint that contain script tags or suspicious JavaScript patterns within the 'rel' or 'option' parameters.
