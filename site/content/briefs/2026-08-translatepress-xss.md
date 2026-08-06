---
title: Stored XSS in TranslatePress Plugin via URL-Encoded Gettext Markers
slug: 2026-08-translatepress-xss
description: The TranslatePress plugin for WordPress is vulnerable to Stored Cross-Site Scripting due to insufficient input sanitization of URL-encoded gettext markers, allowing unauthenticated attackers to inject persistent malicious scripts.
date: "2026-08-06T09:22:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - wordpress
  - plugin-vulnerability
vendors:
  - WordPress
products:
  - TranslatePress – Translate Multilingual sites with AI Translation (<= 3.2.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-18510
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18510
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit and update the TranslatePress plugin to a version > 3.2.6
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18510
  mitigation_plan:
    - priority: immediate
      action: Review WAF logs for percent-encoded script injection attempts in comment fields
      owner: SOC
      addresses: CVE-2026-18510
      evidence: NVD vulnerability entry
---

The TranslatePress - Translate Multilingual sites with AI Translation plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in versions up to and including 3.2.6. The vulnerability stems from inadequate input sanitization and output escaping when processing URL-encoded gettext markers within comment content. 

Because the malicious payload utilizes percent-encoded characters, it successfully circumvents the WordPress `wp_kses` filtering mechanism, which typically validates tags and attributes. While WordPress's comment moderation feature may introduce a minor delay for unauthenticated users, it does not prevent the persistent injection of the script. Once successfully injected into a comment, the script executes within the context of any user who views the compromised page. This poses a significant risk for administrative account compromise or session hijacking, as the script triggers automatically upon page load.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of victims viewing affected pages. This can lead to session hijacking, unauthorized actions performed on behalf of authenticated users, or the redirection of visitors to malicious sites. The vulnerability affects all sites running TranslatePress versions 3.2.6 and earlier.

## Recommendation

* Immediately update the TranslatePress plugin to the latest available version beyond 3.2.6.
* If updating is not possible, disable the comment feature or utilize a Web Application Firewall (WAF) to block requests containing anomalous URL-encoded patterns commonly associated with XSS payloads targeting gettext markers.
* Deploy webserver logging to monitor for anomalous POST requests containing encoded script tags in comment submission parameters.
