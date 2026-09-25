---
title: Stored XSS in Fancy Product Designer WordPress Plugin (CVE-2026-84279)
slug: 2026-09-fancy-product-designer-xss
description: An unauthenticated stored cross-site scripting vulnerability in the Fancy Product Designer WordPress plugin allows attackers to inject malicious scripts via the output_format parameter.
date: "2026-09-25T08:54:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fancy_product_designer:fancy_product_designer:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - Fancy Product Designer
products:
  - Fancy Product Designer (<= 6.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Fancy Product Designer plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'output_format' parameter.
    confidence_band: high
cves:
  - id: CVE-2026-84279
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84279
rules:
  - title: Detect CVE-2026-84279 Exploitation - Stored XSS via fpd_pr_export
    description: Detects exploitation of CVE-2026-84279 where malicious scripts are injected via the output_format parameter in the fpd_pr_export AJAX action.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Fancy Product Designer to version > 6.5.2
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-84279 vulnerability description
  hunt_leads:
    - lead: Search web logs for previous instances of <script tags in fpd_pr_export requests
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source describes vulnerability as exploitable via AJAX action
  mitigation_plan:
    - priority: immediate
      action: Disable Pro Export/Genius feature
      owner: IT Operations
      addresses: CVE-2026-84279
      evidence: Vulnerability requires Pro Export/Genius feature to be active
---

The Fancy Product Designer plugin for WordPress is affected by a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-84279. The flaw resides in the 'output_format' parameter and affects all versions up to and including 6.5.2. The vulnerability stems from inadequate input sanitization and output escaping within the plugin's code. To exploit this, the 'Pro Export/Genius' feature must be enabled, as the vulnerable 'fpd_pr_export' AJAX action is only registered when this feature is active. An unauthenticated attacker can leverage this flaw to inject arbitrary web scripts into pages. These scripts execute in the context of a victim's browser whenever they access an affected page, potentially leading to unauthorized actions, session hijacking, or credential theft. This vulnerability represents a significant risk to WordPress sites utilizing the affected plugin and feature configuration.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browsers of users viewing the injected content. This could result in unauthorized administrative actions, the theft of session cookies, redirection to malicious domains, or the exfiltration of sensitive user data. The vulnerability impacts all WordPress sites running the vulnerable plugin versions with the specified feature enabled.

## Recommendation

* Immediately update the Fancy Product Designer plugin to the latest version beyond 6.5.2 to remediate CVE-2026-84279.
* Disable the 'Pro Export/Genius' feature if it is not strictly required for site functionality until an update can be applied.
* Monitor web application firewall (WAF) logs for POST requests directed at the 'fpd_pr_export' AJAX action that contain suspicious script tags or JavaScript event handlers in the 'output_format' parameter.
