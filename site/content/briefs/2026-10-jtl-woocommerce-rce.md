---
title: Unauthenticated Arbitrary File Upload in JTL-Connector for WooCommerce
slug: 2026-10-jtl-woocommerce-rce
description: The JTL-Connector for WooCommerce WordPress plugin is vulnerable to unauthenticated remote code execution via a flaw in session handling and file validation.
date: "2026-10-14T04:35:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:jtl-software:jtl-connector_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - rce
  - cve-2026-87855
vendors:
  - JTL-Software
products:
  - JTL-Connector for WooCommerce (<= 2.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The JTL-Connector for WooCommerce plugin for WordPress is vulnerable to Arbitrary File Upload... this makes it possible for unauthenticated attackers to upload files.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-87855
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87855
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update JTL-Connector for WooCommerce to the latest version beyond 2.4.3
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to and including 2.4.3
  mitigation_plan:
    - priority: immediate
      action: Monitor/Block unauthorized POST requests to plugin upload endpoints
      owner: SOC
      addresses: CVE-2026-87855
      evidence: Arbitrary file upload via saveImage/handleImagePush functions
---

The JTL-Connector for WooCommerce plugin for WordPress contains a critical arbitrary file upload vulnerability, identified as CVE-2026-87855, affecting all versions up to and including 2.4.3. The flaw stems from the `startSession()` function, which incorrectly validates the `jtlauth` parameter, permitting unauthenticated sessions if the parameter is empty. Once a session is established, attackers can leverage the `handleImagePush()` function. This function fails to perform adequate file type validation, allowing for the upload of arbitrary files. By uploading a malicious script, such as a PHP web shell, an attacker can achieve remote code execution on the underlying web server. This vulnerability carries a CVSS v3.1 base score of 9.8, reflecting its potential for total system compromise in affected WordPress environments.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code with the privileges of the web server user. This could lead to full site takeover, data exfiltration from the WooCommerce database, or the deployment of persistent backdoors within the WordPress environment. All WordPress sites running JTL-Connector for WooCommerce version 2.4.3 or older are considered at risk.

## Recommendation

- Immediately update the JTL-Connector for WooCommerce plugin to the latest available version (greater than 2.4.3) once a patch is released by JTL-Software.
- Implement strict file upload filtering at the web application firewall (WAF) level to block requests containing suspicious file extensions or contents targeting plugin upload directories.
- Review web server access logs for anomalous `POST` requests to endpoints associated with the JTL-Connector, particularly those interacting with image upload functionalities.
