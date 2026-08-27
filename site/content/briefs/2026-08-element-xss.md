---
title: Cross-Site Scripting Vulnerability in Element maps-ng
slug: 2026-08-element-xss
description: A stored cross-site scripting (XSS) vulnerability in the si-map component of Element maps-ng allows unauthenticated attackers to execute arbitrary scripts in a victim's browser via crafted map pin tooltips.
date: "2026-08-27T13:40:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - patch-management
vendors:
  - Element
products:
  - maps-ng
cves:
  - id: CVE-2026-66155
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66155
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Element maps-ng to version V47.12.3, V48.11.3, or V49.16.1
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-66155 patch requirements
  mitigation_plan:
    - priority: immediate
      action: Configure strict CSP headers to block inline script execution
      owner: IT Operations
      addresses: CVE-2026-66155
      evidence: General mitigation for stored XSS vulnerabilities
---

Element maps-ng is affected by a high-severity cross-site scripting (XSS) vulnerability tracked as CVE-2026-66155. The flaw resides in the 'si-map' component, specifically within the handling of the 'points' property responsible for rendering tooltip labels on map pins. Due to the failure to properly neutralize user-controllable input, an attacker can supply malicious payloads as part of the map data. When a user interacts with a map containing these pins, specifically by hovering over them, the browser executes the injected JavaScript code. This vulnerability impacts versions V47, V48, and V49 of the product, with fixed versions identified as V47.12.3, V48.11.3, and V49.16.1 respectively. Successful exploitation enables session hijacking, unauthorized actions on behalf of the user, or redirection to malicious sites.

## Impact

The vulnerability carries a CVSS v3.1 base score of 7.6. Impacted organizations using vulnerable versions of maps-ng to display interactive maps may be susceptible to account takeover or information theft if users with high-level access interact with manipulated map pins. Given the nature of XSS, the attack is silent to the user and operates within the security context of the affected web application.

## Recommendation

* Patch Element maps-ng to the identified safe versions (V47.12.3, V48.11.3, or V49.16.1) immediately to address CVE-2026-66155.
* Implement or update Content Security Policy (CSP) headers on web servers hosting maps-ng to restrict the execution of inline scripts and unauthorized external resources.
* Audit web application logs for HTTP requests containing abnormal script characters or excessive payload lengths directed toward the si-map data endpoints.
