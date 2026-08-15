---
title: Unauthenticated Arbitrary File Deletion in RapiSafe WordPress Plugin
slug: 2026-08-rapisafe-file-deletion
description: The RapiSafe WordPress plugin contains a vulnerability in its AJAX upload handler allowing unauthenticated attackers to delete arbitrary server files, potentially leading to remote code execution.
date: "2026-08-15T04:16:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - RapiSafe – Secure Multi File Upload for Contact Form 7 (<= 1.0.4)
cves:
  - id: CVE-2026-14484
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14484
rules:
  - title: Detects CVE-2026-14484 Exploitation - Arbitrary File Deletion in RapiSafe Plugin
    description: Detects potential exploitation of CVE-2026-14484 by identifying POST requests to the RapiSafe AJAX remove upload endpoint with suspicious file path patterns.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1565.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch RapiSafe plugin to version 1.0.5 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-14484 advisory recommends patching to address vulnerability
  mitigation_plan:
    - priority: immediate
      action: Block or audit access to the RapiSafe AJAX upload removal endpoint via WAF
      owner: SOC
      addresses: CVE-2026-14484
      evidence: Vulnerability allows unauthenticated file deletion
---

The RapiSafe - Secure Multi File Upload for Contact Form 7 plugin for WordPress is affected by an arbitrary file deletion vulnerability identified as CVE-2026-14484. The vulnerability resides in the 'handleAjaxRemoveUpload' function, which fails to properly validate file paths during the deletion process. Because the security nonce required to authorize the AJAX call is exposed globally in the client-side JavaScript object 'RSMFCF7Vars.nonce' on all pages where the plugin is active, any unauthenticated user can craft malicious requests to delete files on the host server. An attacker can leverage this primitive to delete sensitive configuration files such as 'wp-config.php', which often results in the site reverting to an unconfigured state or forcing a re-installation that can lead to remote code execution. This vulnerability affects all versions up to and including 1.0.4.

## Attack Chain

1. Attacker navigates to a public-facing WordPress page that utilizes the RapiSafe plugin.
2. Attacker inspects the page source or browser console to locate the 'RSMFCF7Vars.nonce' variable.
3. Attacker extracts the valid security nonce required for plugin AJAX requests.
4. Attacker constructs an HTTP POST request targeting the 'handleAjaxRemoveUpload' endpoint.
5. Attacker provides the path to a sensitive target file (e.g., /var/www/html/wp-config.php) in the request parameters.
6. The server validates the stolen nonce as authentic and proceeds with the file deletion process.
7. The target file is deleted from the server filesystem.
8. Attacker observes site downtime or initiates a malicious WordPress installation process to gain full administrative control (RCE).

## Impact

Successful exploitation allows unauthenticated attackers to delete arbitrary files on the WordPress server. This typically results in a complete denial of service for the website or, if the site's configuration file is removed, enables the attacker to perform a fresh WordPress installation. Through this installation process, an attacker can gain administrative access to the platform, resulting in full remote code execution and potential data exfiltration. The severity is marked as critical due to the ease of nonce acquisition and the high-impact nature of the resulting file deletion.

## Recommendation

* Immediately update the 'RapiSafe - Secure Multi File Upload for Contact Form 7' plugin to the latest available version that addresses CVE-2026-14484.
* If an update is not currently available, disable the plugin or restrict access to the affected AJAX endpoints via web application firewall (WAF) rules.
* Monitor web server access logs for anomalous POST requests to the plugin's AJAX handler originating from unauthenticated sessions.
