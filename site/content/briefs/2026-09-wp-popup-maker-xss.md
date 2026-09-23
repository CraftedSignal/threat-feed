---
title: Stored XSS in Popup Maker WordPress Plugin (CVE-2026-87915)
slug: 2026-09-wp-popup-maker-xss
description: The Popup Maker WordPress plugin is vulnerable to Stored Cross-Site Scripting via the 'values[Name]' parameter, allowing unauthenticated attackers to inject malicious scripts that execute in the wp-admin dashboard.
date: "2026-09-18T12:05:29Z"
lastmod: "2026-09-23T02:50:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:popup_maker:popup_maker:*:*:*:*:*:wordpress:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=1C62E152-AB35-510B-88B8-AE64E9E46BD9&utm_source=rss&utm_medium=rss
vendors:
  - WordPress
products:
  - Popup Maker (<= 1.24.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: HTML entities within allowed attribute values survive normalization intact and are later evaluated by the jQuery(link.attr('href')) sink.
    confidence_band: high
cves:
  - id: CVE-2026-87915
    cvss: 7.2
    epss: 0.00473
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87915
  - https://sploitus.com/exploit?id=1C62E152-AB35-510B-88B8-AE64E9E46BD9&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit WordPress installations for Popup Maker version <= 1.24.0 and update to latest version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-87915
  mitigation_plan:
    - priority: immediate
      action: Update Popup Maker plugin to a version released after 1.24.0.
      owner: IT Operations
      addresses: CVE-2026-87915
updates:
  - at: "2026-09-23T02:50:43Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=1C62E152-AB35-510B-88B8-AE64E9E46BD9&utm_source=rss&utm_medium=rss
---

The Popup Maker - Boost Sales, Conversions, Optins, Subscribers with the Ultimate WP Popup Builder plugin for WordPress contains a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-87915, affecting all versions up to and including 1.24.0. The vulnerability exists due to inadequate input sanitization and output escaping of the 'values[Name]' parameter. 

Attackers can exploit this flaw by submitting crafted payloads that bypass standard WordPress sanitization functions. Specifically, HTML entities within allowed attribute values are not correctly normalized. These malicious strings are subsequently processed by the jQuery(link.attr('href')) sink in the 'wp-admin/js/common.js' script when an administrator or privileged user interacts with a contextual help tab anchor within the WordPress dashboard. This leads to the execution of arbitrary JavaScript in the victim's browser session, potentially resulting in session hijacking, administrative action spoofing, or further site compromise.

## Impact

The vulnerability poses a significant risk to WordPress site administrators. If exploited, an unauthenticated attacker can execute arbitrary scripts within the context of a privileged user's session. This could lead to full administrative account takeover, unauthorized modification of site content, or the installation of malicious backdoors on the affected WordPress instance. The attack is particularly concerning as it triggers via common administrative interface interactions, increasing the likelihood of successful exploitation against site owners.

## Recommendation

Prioritize the immediate update of the Popup Maker plugin to the latest version. Monitor web server access logs for anomalous POST requests directed at plugin configuration endpoints that include unusual attribute values or encoded characters.
