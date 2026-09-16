---
title: Stored XSS in WP-Lister Lite for eBay WordPress Plugin
slug: 2026-09-wp-lister-xss
description: The WP-Lister Lite for eBay plugin for WordPress contains a Stored Cross-Site Scripting vulnerability in its AJAX Cron Handler allowing unauthenticated script injection.
date: "2026-09-16T05:46:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp-lister:wp-lister_lite_for_ebay:*:*:*:*:*:wordpress:*:*
vendors:
  - WP-Lister
products:
  - WP-Lister Lite for eBay (<= 3.8.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WP-Lister Lite for eBay plugin for WordPress is vulnerable to Stored Cross-Site Scripting via AJAX Cron Handler Request Parameter in all versions up to, and including, 3.8.9 due to insufficient input sanitization and output escaping.
    confidence_band: high
cves:
  - id: CVE-2026-18595
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18595
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade WP-Lister Lite for eBay to the latest version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18595 remediation requires patching vulnerable plugin versions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the version succeeding 3.8.9
      owner: IT Operations
      addresses: CVE-2026-18595
      evidence: NVD vulnerability disclosure
---

The WP-Lister Lite for eBay plugin for WordPress, in versions up to and including 3.8.9, is affected by a Stored Cross-Site Scripting (XSS) vulnerability. The flaw resides in the AJAX Cron Handler, which fails to perform adequate input sanitization and output escaping on request parameters. This vulnerability allows an unauthenticated attacker to inject malicious JavaScript into the plugin settings or associated pages. When an administrative user or other authenticated user views the compromised page, the attacker-supplied script executes within the context of the victim's browser session. This can lead to unauthorized actions, session hijacking, or the defacement of the affected WordPress site. Defenders should monitor web logs for anomalous POST requests directed at the plugin's AJAX endpoints and ensure all plugins are updated to the latest version.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary web scripts in the browser of users accessing the affected site. This could result in unauthorized administrative actions, the theft of session cookies, or further compromise of the WordPress environment. The vulnerability impacts all users of WP-Lister Lite for eBay running versions 3.8.9 or earlier.

## Recommendation

Update the WP-Lister Lite for eBay plugin to the latest version immediately to remediate CVE-2026-18595. In environments where patching is delayed, monitor server access logs for suspicious input patterns within requests targeting plugin AJAX endpoints.
