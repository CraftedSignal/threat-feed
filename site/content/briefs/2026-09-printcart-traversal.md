---
title: Directory Traversal in Printcart Web to Print Product Designer for WooCommerce
slug: 2026-09-printcart-traversal
description: The Printcart Web to Print Product Designer for WooCommerce plugin contains a directory traversal vulnerability that allows unauthenticated attackers to read arbitrary server files.
date: "2026-09-18T10:05:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:printcart:web_to_print_product_designer_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - Printcart
products:
  - Web to Print Product Designer for WooCommerce (<= 2.8.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Printcart Web to Print Product Designer for WooCommerce plugin for WordPress is vulnerable to Directory Traversal in all versions up to, and including, 2.8.5 via the 'mockups' parameter.
    confidence_band: high
cves:
  - id: CVE-2026-14323
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14323
rules:
  - title: Detects CVE-2026-14323 Exploitation - Directory Traversal in Printcart Plugin
    description: Detects exploitation attempts against CVE-2026-14323 by identifying directory traversal sequences in the mockups parameter of WordPress plugin requests.
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Printcart Web to Print Product Designer for WooCommerce to the latest version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-14323 indicates versions <= 2.8.5 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to filter directory traversal patterns in the 'mockups' parameter.
      owner: SOC
      addresses: CVE-2026-14323
      evidence: Vulnerability allows arbitrary file read via 'mockups' parameter.
---

The Printcart Web to Print Product Designer for WooCommerce plugin for WordPress is vulnerable to a directory traversal flaw in versions 2.8.5 and earlier. The vulnerability exists within the 'mockups' parameter, allowing unauthenticated attackers to access and read sensitive files from the underlying server filesystem. 

The exploitation process is simplified by the plugin's insecure implementation of nonce validation. Unauthenticated users can retrieve a valid 'nbdesigner-get-data' nonce from the 'nbd_check_use_logged_in' AJAX endpoint. Furthermore, if the 'NBDESIGNER_ENABLE_NONCE' constant is explicitly set to false, the security gate is removed entirely, allowing direct exploitation of the traversal vulnerability. This flaw poses a significant risk to affected WordPress installations, as it facilitates the exfiltration of sensitive configuration files, including wp-config.php, which often contains database credentials.
