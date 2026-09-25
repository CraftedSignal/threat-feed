---
title: Authorization Bypass in Customer Reviews for WooCommerce Plugin
slug: 2026-09-woocommerce-auth-bypass
description: An authorization bypass vulnerability in the Customer Reviews for WooCommerce plugin for WordPress allows unauthenticated attackers to delete arbitrary files from the WordPress Media Library.
date: "2026-09-25T10:51:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:woocommerce:customer_reviews_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - vulnerability
  - cve-2026-89055
vendors:
  - WordPress
products:
  - Customer Reviews for WooCommerce (<= 5.120.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for unauthenticated attackers to permanently delete arbitrary attachments from the Media Library.
    confidence_band: high
cves:
  - id: CVE-2026-89055
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89055
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Web Security Team
  immediate_actions:
    - action: Update Customer Reviews for WooCommerce plugin to latest version.
      owner: IT Operations
      due: 24h
      evidence: Plugin is vulnerable in all versions up to 5.120.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Customer Reviews for WooCommerce to version > 5.120.0.
      owner: IT Operations
      addresses: CVE-2026-89055
      evidence: NVD vulnerability disclosure specifies versions up to 5.120.0 are vulnerable.
---

The Customer Reviews for WooCommerce plugin for WordPress, in all versions up to and including 5.120.0, contains an authorization bypass vulnerability (CVE-2026-89055). The flaw originates from the plugin's failure to properly verify user permissions within a specific handler. This security oversight allows unauthenticated attackers to permanently delete arbitrary files, including sensitive administrative assets like product logos, documents, and images stored in the WordPress Media Library. The vulnerability is accessible through publicly shared review-form links, which contain a 13-hexadecimal formId and the necessary nonce to trigger the handler without requiring a valid WordPress session or user account. An attacker can leverage this by injecting attachment IDs into a review process that, when trashed and purged, results in the deletion of those specific items. Given the potential for destructive impact on site content and administrative configuration, this vulnerability represents a significant risk to site integrity.

## Impact

Successful exploitation results in the unauthorized, permanent deletion of files from the WordPress Media Library. This can lead to site defacement, loss of critical business documentation, and disruption of e-commerce storefronts by removing product images. If widely targeted, this vulnerability could impact numerous WordPress instances utilizing this specific WooCommerce extension.

## Recommendation

1. Immediately update the Customer Reviews for WooCommerce plugin to the latest version (above 5.120.0) to address the authorization bypass.
2. Audit WordPress Media Library logs or integrity checkers if site tampering is suspected.
3. Monitor web server logs for suspicious requests to review-form handlers that do not correspond to legitimate customer interaction patterns.
