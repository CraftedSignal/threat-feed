---
title: Arbitrary File Upload in Printcart WooCommerce Plugins
slug: 2026-10-woocommerce-plugin-rce
description: An unauthenticated arbitrary file upload vulnerability in the Printcart Store (PCDesigner / NB Designer) WooCommerce plugin allows remote code execution via AJAX parameter manipulation.
date: "2026-10-14T04:35:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:printcart:pcdesigner:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:printcart:nb_designer:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - rce
  - file-upload
  - ecommerce
vendors:
  - Printcart
products:
  - PCDesigner (<= 2.9.1)
  - NB Designer (<= 2.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Printcart Store plugin for WooCommerce is vulnerable to unauthenticated arbitrary file upload leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to write a .php file to a web-served, PHP-executing location.
    confidence_band: high
cves:
  - id: CVE-2026-93388
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93388
rules:
  - title: Detect CVE-2026-93388 Exploitation - Arbitrary File Upload via NB Designer
    description: Detects exploitation of CVE-2026-93388 by monitoring for suspicious POST requests to admin-ajax.php involving the nbdesigner plugin and file extension bypass indicators.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: Plugin is vulnerable to unauthenticated file upload
  mitigation_plan:
    - priority: immediate
      action: Upgrade PCDesigner and NB Designer plugins to version 2.9.2 or later when available.
      owner: IT Operations
      addresses: CVE-2026-93388
      evidence: Plugin is vulnerable up to version 2.9.1
---

The Printcart Store plugins, specifically PCDesigner and NB Designer for WooCommerce, are vulnerable to unauthenticated remote code execution due to improper input validation in the 'nbdesigner_copy_image_from_url' AJAX action. All versions up to and including 2.9.1 are affected. An attacker can exploit this by utilizing the 'nbd_check_use_logged_in' endpoint to retrieve a valid save-design nonce. Following this, the attacker targets the 'nbdesigner_copy_image_from_url' AJAX action, specifically the Google Drive branch. By manipulating the 'gapi[name]' parameter, the attacker can bypass existing file extension allow-lists that typically restrict files to image formats (jpg, jpeg, png, gif). This allows the attacker to write an arbitrary .php file to the 'wp-content/uploads/nbdesigner/temp/' directory, which is web-accessible and parsed by the server. Successful exploitation enables the execution of arbitrary code under the web server user context.

## Attack Chain

1. Attacker sends a request to the 'nbd_check_use_logged_in' endpoint to obtain a valid nonce, even as an unauthenticated user.
2. Attacker prepares a remote Google Drive source containing a malicious PHP payload.
3. Attacker initiates an HTTP POST request to the 'admin-ajax.php' file triggering the 'nbdesigner_copy_image_from_url' action.
4. Attacker includes the required nonce and targets the Google Drive branch of the function.
5. Attacker injects a filename ending in .php via the 'gapi[name]' parameter to bypass extension filtering.
6. The plugin fetches the malicious content from the attacker-controlled Google Drive URL.
7. The plugin writes the malicious PHP file to 'wp-content/uploads/nbdesigner/temp/'.
8. Attacker accesses the newly created file via a browser to trigger remote code execution.

## Impact

Successful exploitation leads to full remote code execution on the WordPress host. This permits unauthorized access to sensitive application data, database contents, and the potential for lateral movement within the network. All instances of the Printcart Store plugins up to version 2.9.1 are affected, exposing e-commerce sites to complete compromise.

## Recommendation

* Upgrade to the latest version of PCDesigner and NB Designer immediately upon the release of a security patch by Printcart.
* Monitor access logs for requests to 'admin-ajax.php' containing parameters related to 'nbdesigner_copy_image_from_url' combined with suspicious file extensions in the query string.
* Restrict write access to the 'wp-content/uploads/nbdesigner/temp/' directory if possible, or implement server-side rules to prevent the execution of PHP files within the uploads directory.
* Utilize the detection rule provided below to identify exploitation attempts targeting the AJAX action.
