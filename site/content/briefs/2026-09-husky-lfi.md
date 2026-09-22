---
title: Local File Inclusion in HUSKY Products Filter for WooCommerce
slug: 2026-09-husky-lfi
description: The HUSKY Products Filter for WooCommerce Professional plugin (<= 1.4.4) is vulnerable to unauthenticated Local File Inclusion (LFI) due to inadequate nonce protection, allowing remote code execution via arbitrary PHP file inclusion.
date: "2026-09-22T08:34:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:husky:products_filter_for_woocommerce_professional:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - lfi
  - web-application
vendors:
  - HUSKY
products:
  - Products Filter for WooCommerce Professional (<= 1.4.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to include and execute arbitrary .php files on the server
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where .php file types can be uploaded and included.
    confidence_band: high
cves:
  - id: CVE-2026-92969
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92969
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch HUSKY Products Filter for WooCommerce Professional plugin to the latest version beyond 1.4.4.
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in all versions up to 1.4.4.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to a version > 1.4.4.
      owner: IT Operations
      addresses: CVE-2026-92969
      evidence: NVD states all versions up to 1.4.4 are vulnerable.
---

The HUSKY - Products Filter for WooCommerce Professional plugin for WordPress contains a critical Local File Inclusion (LFI) vulnerability tracked as CVE-2026-92969. This flaw affects all versions up to and including 1.4.4. The vulnerability stems from improper validation of the 'shortcode' parameter in the plugin's front-end processing logic. While the plugin implements a nonce check using 'woof_front_nonce', this value is exposed to all site visitors via inline JavaScript on every front-end page, rendering the security control ineffective. Consequently, unauthenticated attackers can leverage this LFI to include and execute arbitrary PHP files located on the web server. This access enables attackers to bypass access controls, exfiltrate sensitive data, or achieve full Remote Code Execution (RCE) if they can successfully place a malicious payload within a file accessible to the server process.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary PHP code on the underlying web server hosting the WordPress instance. This can lead to total site compromise, including database exfiltration, unauthorized modification of site content, and potential lateral movement within the hosting environment.

## Recommendation

Update the HUSKY - Products Filter for WooCommerce Professional plugin to the latest available patched version immediately. Monitor web server access logs for anomalous POST or GET requests targeting the WooCommerce filter endpoints containing directory traversal sequences or references to unexpected file extensions in the 'shortcode' parameter.
