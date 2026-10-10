---
title: Stored Cross-Site Scripting in WPAdverts Plugin
slug: 2026-10-wpadverts-xss
description: The WPAdverts plugin for WordPress contains a stored XSS vulnerability (CVE-2026-100178) that allows unauthenticated attackers to inject malicious scripts via the 'adverts_location' parameter.
date: "2026-10-10T09:51:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpadverts:classifieds_plugin:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - WPAdverts
products:
  - WPAdverts – Classifieds Plugin (<= 2.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: injected web scripts... will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-100178
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100178
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update WPAdverts to latest version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-100178 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade WPAdverts to version above 2.3.4
      owner: IT Operations
      addresses: CVE-2026-100178
      evidence: Source advisory
---

The WPAdverts - Classifieds Plugin for WordPress is affected by a stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-100178. The vulnerability exists in versions up to and including 2.3.4 and stems from insufficient input sanitization and output escaping on the 'adverts_location' parameter. This flaw allows an unauthenticated attacker to inject arbitrary web scripts into the plugin's classifieds listings. These scripts are subsequently executed in the browser of any user, including administrators, who views the compromised page. This poses a significant risk for session hijacking, unauthorized actions performed on behalf of authenticated users, or the redirection of visitors to malicious sites. Defenders should prioritize updating to the latest secure version of the plugin as soon as it becomes available to mitigate this injection risk.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site utilizing a vulnerable version of the WPAdverts plugin.
2. The attacker crafts an HTTP request containing malicious JavaScript payloads within the 'adverts_location' parameter.
3. The attacker submits this request to the application, exploiting the lack of input sanitization in the plugin's endpoint.
4. The malicious script is stored directly in the WordPress database associated with the classifieds advertisement.
5. An unsuspecting user, such as a site administrator or visitor, navigates to the compromised advertisement page.
6. The web server renders the stored payload within the victim's browser session.
7. The browser executes the injected script with the permissions of the victim's active session.
8. The attacker achieves their objective, such as session token theft or unauthorized administrative actions.

## Impact

Successful exploitation of this stored XSS vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in the context of other users' sessions. This can lead to account takeover, unauthorized modification of site content, or the distribution of further malicious content to site visitors. Given the nature of WordPress plugins, this vulnerability affects any site running version 2.3.4 or earlier.

## Recommendation

1. Update the WPAdverts - Classifieds Plugin to the latest version released after 2.3.4 to ensure the 'adverts_location' parameter is properly sanitized.
2. Implement a Content Security Policy (CSP) to restrict the execution of unauthorized inline scripts as a defense-in-depth measure.
3. Monitor web server logs for HTTP requests containing suspicious script tags or JavaScript event handlers (e.g., onerror, onload) targeting the URL structure associated with WPAdverts.
4. Perform a security review of site plugins and disable those that have not received recent security updates or are no longer maintained.
