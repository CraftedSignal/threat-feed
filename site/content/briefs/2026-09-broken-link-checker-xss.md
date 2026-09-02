---
title: CVE-2026-75528 Stored XSS in Broken Link Checker WordPress Plugin
slug: 2026-09-broken-link-checker-xss
description: The Broken Link Checker WordPress plugin up to version 2.4.13 is vulnerable to Stored Cross-Site Scripting, allowing unauthenticated attackers to execute malicious scripts in the administrative session context.
date: "2026-09-02T09:12:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:broken_link_checker_project:broken_link_checker:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Broken Link Checker (<= 2.4.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-75528
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75528
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Broken Link Checker plugin to a version > 2.4.13
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies version 2.4.13 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.4.14 or later
      owner: IT Operations
      addresses: CVE-2026-75528
      evidence: NVD advisory
---

The Broken Link Checker plugin for WordPress, in versions up to and including 2.4.13, contains a security flaw resulting in Stored Cross-Site Scripting (XSS). The vulnerability stems from insufficient input sanitization and output escaping within the plugin's Comment Author URL and Link Log processing functions. An unauthenticated attacker can craft a malicious URL and submit it as a comment author link. When an administrator performs the plugin's standard "dismiss-and-recheck" workflow, the plugin fetches the malicious URL. The attacker's server then issues a redirect to a secondary URL containing an HTML/JavaScript payload. This payload is stored verbatim in the plugin's link log, where it executes upon being rendered in an administrative session. This vulnerability poses a significant risk to the integrity of the WordPress administrative environment.

## Impact

Successful exploitation of CVE-2026-75528 allows an unauthenticated attacker to execute arbitrary JavaScript in the context of an administrator's browser session. This could lead to account takeover, unauthorized administrative actions, or the injection of further malicious content into the site, impacting any WordPress installation using the vulnerable plugin version.

## Recommendation

Update the Broken Link Checker plugin to the latest version, ensuring it exceeds 2.4.13. Security operations should review administrative access logs for unusual patterns involving the "dismiss-and-recheck" functionality and monitor web application firewall (WAF) logs for POST requests to WordPress comment submission endpoints containing non-standard URL schemes or script-like patterns.
