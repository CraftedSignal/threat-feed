---
title: Unauthenticated Remote Code Execution in Pix for WooCommerce
slug: 2026-08-pix-woocommerce-rce
description: A critical vulnerability (CVE-2026-3891) in the Pix for WooCommerce WordPress plugin allows unauthenticated attackers to upload and execute arbitrary PHP files via vulnerable AJAX handlers.
date: "2026-08-03T18:11:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - rce
  - cve-2026-3891
products:
  - Pix for WooCommerce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can abuse this flaw to upload arbitrary PHP files to a publicly accessible directory and achieve remote code execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: The plugin fails to enforce proper authorization and file-type checks, allowing an attacker to upload a webshell.
    confidence_band: high
cves:
  - id: CVE-2026-3891
    cvss: 9.8
    epss: 0.08797
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3891
  - https://sploitus.com/exploit?id=9B7BB601-6D78-565A-8C60-BC91A8DCF428
rules:
  - title: Detect CVE-2026-3891 Exploitation Attempt
    description: Detects exploitation attempts against Pix for WooCommerce by monitoring for specific AJAX actions used in the unauthenticated file upload chain.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule for AJAX actions
      owner: Detection Engineering
      due: 24h
      evidence: Plugin uses vulnerable AJAX handlers which are logged in web access logs.
  hunt_leads:
    - lead: Search logs for POST /wp-admin/admin-ajax.php with specified plugin actions
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit automation targets these specific AJAX actions.
  mitigation_plan:
    - priority: immediate
      action: Update Pix for WooCommerce plugin
      owner: IT Operations
      addresses: CVE-2026-3891
      evidence: Plugin version 1.5.0 is vulnerable; update is the primary mitigation.
---

CVE-2026-3891 is a critical vulnerability affecting the Pix for WooCommerce WordPress plugin in versions up to and including 1.5.0. The vulnerability stems from two AJAX actions, `lkn_pix_for_woocommerce_generate_nonce` and `lkn_pix_for_woocommerce_c6_save_settings`, which lack proper authentication and authorization checks. An unauthenticated attacker can first request a valid security nonce from the public-facing `admin-ajax.php` endpoint and subsequently use that nonce to trigger the `c6_save_settings` action. 

This second action improperly handles file uploads by failing to validate the file type or verify user permissions, permitting the upload of arbitrary PHP files into a publicly accessible directory. The files are stored in `wp-content/plugins/payment-gateway-pix-for-woocommerce/Includes/files/certs_c6/`, where they can be executed directly by the web server. Successful exploitation grants the attacker remote code execution with the privileges of the web server user, potentially leading to full site takeover, data exfiltration, and establishment of persistent backdoors.

## Attack Chain

1. The attacker performs an unauthenticated POST request to `wp-admin/admin-ajax.php` with the action `lkn_pix_for_woocommerce_generate_nonce` and `action_name=lkn_pix_for_woocommerce_c6_settings_nonce`.
2. The server returns a valid security nonce in the JSON response.
3. The attacker crafts a multipart POST request to `wp-admin/admin-ajax.php` using the action `lkn_pix_for_woocommerce_c6_save_settings`.
4. The request includes the previously acquired nonce and an arbitrary file (e.g., `shell.php`) in the `certificate_crt_path` parameter.
5. The plugin saves the malicious file to `wp-content/plugins/payment-gateway-pix-for-woocommerce/Includes/files/certs_c6/`.
6. The attacker navigates their browser to the direct URL of the uploaded file to trigger execution.
7. The server executes the PHP payload, providing the attacker with remote command execution capabilities.

## Impact

Successful exploitation results in full Remote Code Execution (RCE) on the WordPress server. Attackers can leverage this access to steal sensitive configuration data such as `wp-config.php`, compromise database credentials, exfiltrate customer information, modify system files to plant backdoors, or gain administrative access to the WordPress site. The vulnerability affects all users running Pix for WooCommerce versions 1.5.0 and earlier.

## Recommendation

- Immediately update Pix for WooCommerce to a version later than 1.5.0 that includes the patch for CVE-2026-3891.
- If an update is not immediately available, configure the web server to deny PHP execution within the `certs_c6` directory using `.htaccess` or server configuration blocks.
- Implement a WAF rule to block requests to `admin-ajax.php` containing the `lkn_pix_for_woocommerce_c6_save_settings` action if initiated by unauthorized sources.
- Audit the `certs_c6` directory for any unexpected PHP files and remove them immediately.
- Deploy the provided Sigma rule to detect suspicious AJAX requests and potential webshell uploads.
