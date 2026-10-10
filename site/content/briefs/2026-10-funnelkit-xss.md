---
title: Stored Cross-Site Scripting in FunnelKit for WooCommerce
slug: 2026-10-funnelkit-xss
description: The FunnelKit Funnel Builder for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the shipping_first_name parameter due to insufficient input sanitization.
date: "2026-10-10T09:51:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:funnelkit:funnel_builder_for_woocommerce_checkout:*:*:*:*:*:*:*:*
vendors:
  - FunnelKit
products:
  - FunnelKit – Funnel Builder for WooCommerce Checkout (<= 3.16.0.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-100147
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100147
rules:
  - title: Detect CVE-2026-100147 - Stored XSS Attempt in FunnelKit
    description: Detects potential Stored XSS exploitation by identifying common script injection patterns within POST requests targeting WooCommerce checkout parameters.
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
    - SOC
  immediate_actions:
    - action: Upgrade FunnelKit - Funnel Builder for WooCommerce Checkout to version > 3.16.0.5
      owner: IT Operations
      due: 48h
      evidence: Source states all versions up to 3.16.0.5 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade to fixed version 3.16.0.6 or later
      owner: IT Operations
      addresses: CVE-2026-100147
      evidence: Plugin vulnerability requires version upgrade
---

FunnelKit - Funnel Builder for WooCommerce Checkout, a widely used WordPress plugin, contains a critical Stored Cross-Site Scripting (XSS) vulnerability identified as CVE-2026-100147. This vulnerability exists in all versions up to and including 3.16.0.5. The issue stems from inadequate input sanitization and output escaping on the 'shipping_first_name' parameter. An unauthenticated attacker can supply a malicious payload within this field, which is subsequently stored by the application. When a privileged user, such as an administrator, views the checkout or order details page containing the stored payload, the script executes within their browser session. This can lead to unauthorized actions, session hijacking, or the defacement of the affected WordPress site.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's session. In an administrative context, this could result in full site compromise, unauthorized administrative actions, or the redirection of site traffic. Given the plugin's role in WooCommerce checkout processes, this vulnerability poses a risk to both site integrity and customer data.

## Recommendation

Prioritize the update of the FunnelKit - Funnel Builder for WooCommerce Checkout plugin to a version beyond 3.16.0.5. Detection engineers should inspect web server access logs for anomalous POST requests containing HTML or script tags within checkout-related parameters.
