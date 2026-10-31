---
brief_id: brief-2026-10-31-checkout-files-upload-rce
event_id: brief-2026-10-31-checkout-files-upload-rce
revision: 1
activity_at: "2026-10-31T00:04:37Z"
title: 'Checkout Files Upload for WooCommerce: Unauthenticated Remote Code Execution (CVE-2026-103688)'
slug: 2026-10-checkout-files-upload-rce
description: An unauthenticated file upload vulnerability in the Checkout Files Upload for WooCommerce plugin allows remote attackers to execute arbitrary PHP code due to improper file type validation and exposed AJAX handlers.
date: "2026-10-31T00:04:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:wpwham:checkout_files_upload:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - webshell
  - remote-code-execution
  - file-upload
vendors:
  - WP Wham
products:
  - Checkout Files Upload for WooCommerce (< 2.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated file upload in Checkout Files Upload for WooCommerce allows webshell execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: The original extension is preserved. A .php upload therefore becomes an executable PHP file in a public directory.
    confidence_band: high
cves:
  - id: CVE-2026-103688
    cvss: 9.8
    epss: 0.00611
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103688
  - https://sploitus.com/exploit?id=E10302AB-9FC5-58F1-816F-E1F71C1C27F4
  - https://sploitus.com/exploit?id=E10302AB-9FC5-58F1-816F-E1F71C1C27F4&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-103688 Exploitation - Unauthenticated AJAX File Upload
    description: Detects unauthenticated POST requests to the plugin AJAX endpoint which may indicate an attempt to upload malicious files.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Checkout Files Upload for WooCommerce to version 2.4.0
      owner: IT Operations
      due: 24h
      evidence: Plugin author release note for 2.4.0
  hunt_leads:
    - lead: Search web server logs for PHP files accessed in the uploads directory
      technique_id: T1505.003
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Files are saved to wp-content/uploads/woocommerce_uploads/alg_uploads/checkout_files_upload/
  mitigation_plan:
    - priority: immediate
      action: Configure explicit file extension allow-list in plugin settings
      owner: IT Operations
      addresses: CVE-2026-103688
      evidence: Vulnerability root cause in empty file-type allow-list
---

The Checkout Files Upload for WooCommerce plugin (prior to version 2.4.0) contains an unauthenticated file upload vulnerability tracked as CVE-2026-103688. The vulnerability arises because the plugin fails to enforce file type validation if the "Accepted file types" setting is left blank. The AJAX action `alg_ajax_file_upload` is accessible to unauthenticated users via the `wp_ajax_nopriv_` hook, and the required nonce is exposed to all visitors on the checkout page. Exploitation results in the ability to upload executable PHP files to a public web directory, facilitating remote code execution.

## Attack Chain
1. An attacker identifies a WordPress site running the Checkout Files Upload plugin with an empty "Accepted file types" configuration.
2. The attacker visits the checkout page to retrieve a valid nonce for the `wpwham-checkout-files-upload-0` action.
3. The attacker submits a `multipart/form-data` request to `/wp-admin/admin-ajax.php` containing the nonce, `file_uploader` identifier, and a malicious PHP file.
4. The plugin stores the malicious file in a temporary location and moves it to `wp-content/uploads/woocommerce_uploads/alg_uploads/checkout_files_upload/` upon order creation or submission.
5. The attacker requests the uploaded PHP file directly via the web server to execute arbitrary code with the privileges of the web service user.

## Impact
Successful exploitation allows unauthenticated attackers to execute arbitrary PHP code on the server, leading to full site compromise, data exfiltration, and potential lateral movement within the hosting environment.

## Recommendation
- Update the "Checkout Files Upload for WooCommerce" plugin to version 2.4.0 or later immediately.
- If immediate patching is not possible, configure an explicit "Accepted file types" allow-list (e.g., jpg,jpeg,png,pdf) for every uploader instance in the plugin settings.
- Block direct PHP execution in the uploads directory by adding the following directive to your web server configuration (Nginx or Apache) to prevent webshell execution.
- Audit the `wp-content/uploads/woocommerce_uploads/alg_uploads/checkout_files_upload/` directory for any unexpected files.
