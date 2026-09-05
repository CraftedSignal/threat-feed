---
title: Stored XSS in W3 Total Cache Plugin for WordPress
slug: 2026-09-w3-total-cache-xss
description: The W3 Total Cache plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the LazyLoad Background Mutator, allowing unauthenticated attackers to execute arbitrary scripts after moderator approval.
date: "2026-09-05T07:30:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:w3-edge:w3_total_cache:*:*:*:*:*:wordpress:*:*
tags:
  - web-security
  - xss
  - wordpress
  - cve-2026-78438
vendors:
  - W3 EDGE
products:
  - W3 Total Cache (<= 2.10.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-78438
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78438
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade W3 Total Cache to version 2.10.6 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-78438 indicates version 2.10.5 and below are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Disable Process background images in W3 Total Cache settings
      owner: IT Operations
      addresses: CVE-2026-78438
      evidence: Exploit requires 'Process background images' feature to be enabled
---

The W3 Total Cache plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the LazyLoad Background Mutator feature. This flaw, tracked as CVE-2026-78438, affects all versions up to and including 2.10.5. The vulnerability stems from insufficient input sanitization and output escaping within the plugin's image processing logic. An unauthenticated attacker can inject malicious web scripts into the comment content of a WordPress site. For the exploit to trigger, the target site must have the "Lazy Load Images" feature enabled with the "Process background images" option active. Furthermore, the injected comment must be approved by a moderator before the script becomes active in the front-end rendering of the page, where it will then execute in the context of any user who accesses the compromised page. This vulnerability poses a significant risk for session hijacking, credential theft, or unauthorized actions performed on behalf of legitimate users or administrators.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary scripts in the browsers of users viewing the injected content. This could result in unauthorized administrative actions, the theft of sensitive session cookies, or the redirection of users to malicious infrastructure. The impact is elevated if a site administrator views the injected content, potentially leading to a full site compromise.

## Recommendation

* Upgrade the W3 Total Cache plugin to a version beyond 2.10.5 immediately to resolve CVE-2026-78438.
* Disable the "Process background images" option within the "Lazy Load Images" settings until the update can be applied.
* Audit comment sections for suspicious content, specifically checking for script tags or encoded payloads in comment metadata.
* Implement or review Content Security Policy (CSP) headers to restrict the execution of unauthorized inline scripts.
