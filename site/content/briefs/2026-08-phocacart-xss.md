---
title: Reflected XSS Vulnerability in PhocaCart and mod_phocacart_filter
slug: 2026-08-phocacart-xss
description: An unauthenticated Reflected Cross-Site Scripting (XSS) vulnerability in PhocaCart (CVE-2026-76565) allows attackers to inject malicious JavaScript via price filter parameters.
date: "2026-08-21T18:38:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Phoca
products:
  - PhocaCart (6.1.7)
  - mod_phocacart_filter (6.1.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: An attacker delivers a crafted URL to a victim. When the victim loads the page, the injected event handler executes in their browser.
    confidence_band: high
cves:
  - id: CVE-2026-76565
    epss: 0.00258
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76565
  - https://github.com/advisories/GHSA-2m94-2f44-8q5p
rules:
  - title: Detect CVE-2026-76565 Exploitation - Reflected XSS in PhocaCart
    description: Detects attempts to exploit CVE-2026-76565 by identifying malicious payloads injected into PhocaCart price filter GET parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch PhocaCart to version 6.1.8 or higher.
      owner: IT Operations
      due: 48h
      evidence: PhocaCart 6.1.8 addresses the vulnerable template code.
  hunt_leads:
    - lead: Search web logs for requests to PhocaCart endpoints with price_from or price_to parameters containing double quotes or event handlers.
      technique_id: T1189
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source details the injection of JS payloads into price filter parameters.
  mitigation_plan:
    - priority: immediate
      action: Update to 6.1.8.
      owner: IT Operations
      addresses: CVE-2026-76565
      evidence: Version 6.1.8 includes the fix for the XSS vulnerability.
---

PhocaCart version 6.1.7 and earlier, when used with the mod_phocacart_filter module, contains a reflected Cross-Site Scripting (XSS) vulnerability tracked as CVE-2026-76565. The flaw originates from the application's failure to properly sanitize the 'price_from' and 'price_to' GET parameters before echoing them into HTML value attributes. While the application uses Joomla's 'string' input filter, this only applies 'strip_tags()' and fails to encode HTML special characters such as double quotes. An unauthenticated attacker can leverage this to inject arbitrary JavaScript attributes, such as 'autofocus' and 'onfocus', to trigger code execution in the browser of a victim who visits a crafted URL. This vulnerability impacts the shop frontend, potentially leading to session hijacking, credential harvesting, or unauthorized actions performed under the context of the trusted site.

## Impact

The vulnerability enables attackers to perform unauthorized actions on behalf of authenticated or unauthenticated users browsing the shop. Successful exploitation can lead to session cookie theft, session hijacking, phishing through injected content, or forced redirects to malicious domains. Organizations running PhocaCart 6.1.7 or older with the vulnerable filter module are at risk of client-side attacks targeting their customers and administrative staff.

## Recommendation

* Update the PhocaCart component and the mod_phocacart_filter module to version 6.1.8 or later immediately to patch the injection sink.
* Implement Content Security Policy (CSP) headers to restrict the execution of unauthorized inline scripts as a defense-in-depth measure.
* Monitor web server logs for requests containing suspicious GET parameters with URL-encoded HTML special characters like %22, %27, or %3E in the 'price_from' and 'price_to' fields.
